# frozen_string_literal: true
# name: discourse-promo-digest-injector
# about: Ensures digest includes tag-marked topics near the top (with optional random injection) and posts a run summary to an external endpoint (async, non-blocking). Optionally restricts promo picks to categories the user is "watching". Also (A) requires a minimum number of digests before injecting and (B) stores last 50 digest topic IDs per user (newest digest first, duplicates allowed).
# version: 1.2.9
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "json"
  require "set"
  require "time"

  # ============================================================
  # CONFIG (EDIT HERE)
  # ============================================================
  module ::PromoDigestConfig
    ENABLED = true

    # Don't activate promo insertion logic until user has received at least this many digests
    MIN_DIGESTS_BEFORE_INJECT = 3

    # If you run the digest counter plugin, it stores digest count here (fast path):
    # user.custom_fields["digest_sent_counter"] => "1","2",...
    DIGEST_COUNT_CUSTOM_FIELD = "digest_sent_counter"

    # PROMO SOURCE: Tag name on topics (case-insensitive)
    PROMO_TAG = "helpful"

    # If user is "watching" any categories, only pick promo-tagged topics from those categories.
    # If user is watching none => fallback to all categories.
    USE_WATCHED_CATEGORIES = true
    INCLUDE_WATCHING_FIRST_POST = true # treat "watching first post" as watched too

    # If ANY promo-tagged topic exists in positions 1..MIN_POSITION => do nothing
    MIN_POSITION = 3

    # If above condition fails: in this % of cases do nothing
    COINFLIP_SKIP_PERCENT = 30 # 0..100

    # Otherwise: replace REPLACE_COUNT topics within the top REPLACE_WITHIN_TOP_N digest positions
    REPLACE_WITHIN_TOP_N = 3
    REPLACE_COUNT        = 1

    # Digest list limit (Discourse passes opts[:limit], but we keep a safe default)
    DEFAULT_DIGEST_LIMIT = 50

    # External summary endpoint (set empty to disable posting)
    ENDPOINT_URL = "http://172.17.0.1:8081/digest_inject.php"

    # Optional secret header (leave empty to disable)
    SECRET_HEADER_VALUE = "" # sent as X-Promo-Postback-Secret

    # Log the HTTP status code for the summary POST (in Sidekiq job logs)
    LOG_POST_RESULTS = false

    # HTTP timeouts (seconds) - used in Sidekiq job
    HTTP_OPEN_TIMEOUT = 3
    HTTP_READ_TIMEOUT = 5

    # IMPORTANT: Sidekiq job args should not be huge. This keeps payload smaller.
    # Set false to send full topic objects (title/slug/url). Set true to send IDs only.
    SEND_IDS_ONLY = true

    # Store last 50 digest topics per user (IDs only), newest digest first, duplicates allowed
    LAST_DIGEST_TOPICS_FIELD = "promo_digest_last50_topic_ids" # JSON array of ints (string)
    LAST_DIGEST_TOPICS_MAX   = 50

    # Always ensure first digest topic is from a watched category (if user watches any)
    FORCE_FIRST_TOPIC_FROM_WATCHED_CATEGORY = true

    # % chance to APPLY the "force first topic from watched category" logic.
    # 0   => never apply
    # 100 => always apply
    FORCE_FIRST_TOPIC_WATCHED_COINFLIP_PERCENT = 100 # 0..100

    # NEW:
    # If true:
    #   even when the current first topic is already in a watched category,
    #   we STILL attempt to "refresh" position 0 by choosing randomly among
    #   the newest N watched-category topics in the lookahead window.
    #
    # If false (default):
    #   if the first topic is already watched, do nothing.
    FORCE_FIRST_TOPIC_RANDOMIZE_EVEN_IF_ALREADY_WATCHED = true

    # Choose randomly among the newest N watched-category candidates in the lookahead window.
    # (If fewer than N exist, it randomizes among what's available.)
    FORCE_FIRST_TOPIC_RANDOM_TOP_N = 5

    # If true, the forced-first watched-category candidate must have:
    #   topics.created_at > user's last digest sent time
    # (If user has no previous digest, this constraint is not applied.)
    FORCE_FIRST_TOPIC_REQUIRE_CREATED_AFTER_LAST_DIGEST = true

    # soft fallback when REQUIRE_CREATED... is enabled but no candidates match:
    # - First try "created_at > last_digest" candidates.
    # - If none found, fallback to ANY watched-category topic within lookahead window.
    # In both cases, we choose randomly among the newest N candidates.
    FORCE_FIRST_TOPIC_SOFT_FALLBACK = true

    # How far into the digest we'll look for a watched-category topic to consider for position 0
    FORCE_FIRST_TOPIC_LOOKAHEAD = 50

    # Promo pool recency gate:
    # Only allow promo-candidate topics whose topics.created_at is AFTER the user's last sent digest.
    FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST = true

    # ============================================================
    # PROMO PICK STRATEGY SWITCH
    #
    # "global" (current): pick promo candidates from the whole forum (tagged topics), excluding digest ids.
    #
    # "prefer_digest_list":
    #   1) FIRST try to satisfy replacement slots by SWAPPING IN eligible promo-tagged topics
    #      that are ALREADY IN the digest list (no duplicates possible).
    #   2) Only if not enough are available, FALLBACK to forum-wide candidates OUTSIDE the digest list
    #      and replace the remaining slots (replacement, no insertion).
    # ============================================================
    PROMO_PICK_MODE = "prefer_digest_list" # "global" or "prefer_digest_list"
  end

  PLUGIN_NAME = "discourse-promo-digest-injector"

  # ============================================================
  # ASYNC JOB (NON-BLOCKING HTTP POST)
  # ============================================================
  module ::Jobs
    class PromoDigestSendSummary < ::Jobs::Base
      def execute(args)
        endpoint = args["endpoint_url"].to_s.strip
        return if endpoint.empty?

        payload_json = args["payload_json"].to_s
        return if payload_json.empty?

        secret = args["secret"].to_s
        log_results = args["log_post_results"] == true

        uri = URI.parse(endpoint)

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = (args["open_timeout"] || 3).to_i
        http.read_timeout = (args["read_timeout"] || 5).to_i

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/json"
        req["X-Promo-Postback-Secret"] = secret if secret.strip != ""
        req.body = payload_json

        res = http.request(req)
        Rails.logger.info("[#{PLUGIN_NAME}] async summary POST => #{res.code}") if log_results
      rescue => e
        Rails.logger.warn("[#{PLUGIN_NAME}] async summary POST failed: #{e.class}: #{e.message}")
      end
    end
  end

  module ::PromoDigestInjector
    # ----------------------------
    # Digest count helper (gate)
    # ----------------------------
    def self.user_digest_count(user)
      return 0 if user.nil?

      cf_key = ::PromoDigestConfig::DIGEST_COUNT_CUSTOM_FIELD.to_s.strip
      if cf_key != ""
        cf_val = user.custom_fields[cf_key]
        return cf_val.to_i if cf_val.present?
      end

      min_needed = ::PromoDigestConfig::MIN_DIGESTS_BEFORE_INJECT.to_i
      min_needed = 0 if min_needed < 0
      return 0 if min_needed <= 0

      EmailLog.where(user_id: user.id, email_type: "digest").limit(min_needed).count
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] user_digest_count failed: #{e.class}: #{e.message}")
      0
    end

    # ----------------------------
    # Last digest sent timestamp (used for promo pool filter + optional forced-first constraint)
    # ----------------------------
    def self.last_digest_sent_at_for_user(user)
      return nil if user.nil?

      cache_key = :"promo_digest_last_digest_sent_at_user_#{user.id}"
      return Thread.current[cache_key] if Thread.current.key?(cache_key)

      ts =
        EmailLog
          .where(user_id: user.id, email_type: "digest")
          .order(created_at: :desc)
          .limit(1)
          .pluck(:created_at)
          .first

      Thread.current[cache_key] = ts
      ts
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] last_digest_sent_at_for_user failed: #{e.class}: #{e.message}")
      Thread.current[cache_key] = nil
      nil
    end

    # ----------------------------
    # Store last 50 digest topics (newest digest first; duplicates allowed)
    # ----------------------------
    def self.persist_last_digest_topics(user, topic_ids)
      return if user.nil?

      field = ::PromoDigestConfig::LAST_DIGEST_TOPICS_FIELD.to_s
      return if field.strip.empty?

      max_n = ::PromoDigestConfig::LAST_DIGEST_TOPICS_MAX.to_i
      max_n = 50 if max_n <= 0

      current = Array(topic_ids).map(&:to_i).reject(&:zero?)
      return if current.empty?

      current = current.first(max_n)

      User.transaction do
        u = User.lock.find(user.id)

        prev_json = u.custom_fields[field].to_s
        prev =
          begin
            JSON.parse(prev_json)
          rescue
            []
          end
        prev = Array(prev).map(&:to_i).reject(&:zero?)

        combined = (current + prev).first(max_n)

        u.custom_fields[field] = combined.to_json
        u.save_custom_fields(true)
      end
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] persist_last_digest_topics failed: #{e.class}: #{e.message}")
    end

    # ----------------------------
    # helper to indicate whether current first topic is from watched category
    # ----------------------------
    def self.first_topic_is_watched_category?(user, ids)
      return false if user.nil?
      return false if ids.blank?

      watched_ids = watched_category_ids_for_user(user)
      return false if watched_ids.blank?

      first_id = ids.first.to_i
      return false if first_id <= 0

      cid = Topic.where(id: first_id).pluck(:category_id).first
      return false if cid.nil?

      watched_ids.include?(cid)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] first_topic_is_watched_category? failed: #{e.class}: #{e.message}")
      false
    end

    # ----------------------------
    # Main hook
    # ----------------------------
    def self.maybe_adjust_digest_topics(user, original_relation, opts)
      return original_relation unless ::PromoDigestConfig::ENABLED
      return original_relation unless Thread.current[:promo_digest_in_digest] == true
      return original_relation if user.nil?

      limit = extract_limit(opts)
      original_ids = original_relation.limit(limit).pluck(:id)
      original_ids = Array(original_ids).map(&:to_i).reject(&:zero?)

      # Store initial digest topics (pre-injection) - if any
      persist_last_digest_topics(user, original_ids) if original_ids.present?

      promo_tag = ::PromoDigestConfig::PROMO_TAG.to_s.strip.downcase

      # Always compute user's watched categories for reporting clarity
      user_watched_category_ids = watched_category_ids_for_user(user)

      # ---------- GATE: do not return early; mark skipped + ALWAYS send report ----------
      min_digests_required = ::PromoDigestConfig::MIN_DIGESTS_BEFORE_INJECT.to_i
      min_digests_required = 0 if min_digests_required < 0

      user_digest_count_val = 0
      is_skipped_min_digests = false
      if min_digests_required > 0
        user_digest_count_val = user_digest_count(user)
        is_skipped_min_digests = (user_digest_count_val < min_digests_required)
      end

      tag = promo_tag.empty? ? nil : find_tag_by_name_ci(promo_tag)
      tag_id = tag&.id

      tagged_ids_set =
        if original_ids.present? && tag_id
          fetch_tagged_topic_ids(original_ids, tag_id).to_set
        else
          Set.new
        end

      min_position = ::PromoDigestConfig::MIN_POSITION.to_i
      min_position = 3 if min_position <= 0

      # Skip if any promo-tagged topic already appears in top MIN_POSITION
      has_tagged_in_top =
        if original_ids.present?
          original_ids.first(min_position).any? { |tid| tagged_ids_set.include?(tid) }
        else
          false
        end

      skip_percent = ::PromoDigestConfig::COINFLIP_SKIP_PERCENT.to_i
      skip_percent = 0 if skip_percent < 0
      skip_percent = 100 if skip_percent > 100

      is_skipped_haspromo = has_tagged_in_top
      is_skipped_coinflip = false

      final_ids = original_ids.dup
      injected_ids = []
      replace_indices = []
      attempted_replace = false

      candidate_pool_count = 0
      visible_pool_count = 0

      watched_category_ids = []
      watched_filter_applied = false

      # Recency filter anchor
      last_digest_sent_at = last_digest_sent_at_for_user(user)
      created_after_last_digest_filter_enabled = (::PromoDigestConfig::FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST == true)
      created_after_last_digest_filter_applied = (created_after_last_digest_filter_enabled && last_digest_sent_at.present?)

      promo_pick_mode = ::PromoDigestConfig::PROMO_PICK_MODE.to_s.strip
      promo_pick_mode = "global" if promo_pick_mode.empty?
      prefer_digest_list_mode = (promo_pick_mode == "prefer_digest_list")

      # Debug fields for prefer_digest_list mode
      digest_list_candidates_count = 0
      digest_list_visible_count = 0
      digest_list_picked = []
      fallback_picked = []
      used_fallback_outside_digest = false

      # ============================================================
      # Promo injection block (blocked by min-digests gate)
      # ============================================================
      if !is_skipped_min_digests && !is_skipped_haspromo && original_ids.present?
        if rand(100) < skip_percent
          is_skipped_coinflip = true
        else
          replace_within_top_n = ::PromoDigestConfig::REPLACE_WITHIN_TOP_N.to_i
          replace_within_top_n = 3 if replace_within_top_n <= 0

          replace_count = ::PromoDigestConfig::REPLACE_COUNT.to_i
          replace_count = 1 if replace_count <= 0

          window = [replace_within_top_n, final_ids.length].min
          if window > 0 && replace_count > 0
            attempted_replace = true
            replace_indices = (0...window).to_a.sample([replace_count, window].min)

            if prefer_digest_list_mode
              tmp_ids = final_ids.dup

              eligible_set, cand_ct, vis_ct, watched_ids, watched_applied =
                eligible_promo_set_within_digest_list(
                  user,
                  tag_id: tag_id,
                  digest_ids: original_ids,
                  created_after: (created_after_last_digest_filter_applied ? last_digest_sent_at : nil)
                )

              digest_list_candidates_count = cand_ct
              digest_list_visible_count = vis_ct
              watched_category_ids = watched_ids
              watched_filter_applied = watched_applied

              _satisfied, swapped_in_ids, remaining_indices =
                swap_eligible_promos_into_indices(
                  tmp_ids,
                  replace_indices,
                  eligible_set
                )

              digest_list_picked = swapped_in_ids.dup

              if remaining_indices.any?
                remaining_need = remaining_indices.length

                fallback_ids, cand_b, vis_b, watched_b, watched_applied_b =
                  pick_random_promo_topic_ids(
                    user,
                    tag_id: tag_id,
                    exclude_ids: original_ids, # ensure "outside digest list"
                    limit: remaining_need,
                    created_after: (created_after_last_digest_filter_applied ? last_digest_sent_at : nil)
                  )

                used_fallback_outside_digest = fallback_ids.present?
                fallback_picked = fallback_ids.dup

                candidate_pool_count = cand_ct + cand_b
                visible_pool_count = vis_ct + vis_b

                watched_category_ids = watched_b
                watched_filter_applied = watched_applied_b

                if fallback_ids.length == remaining_need
                  remaining_indices.each_with_index do |idx, j|
                    tmp_ids[idx] = fallback_ids[j]
                  end

                  final_ids = tmp_ids
                  injected_ids = swapped_in_ids + fallback_ids
                else
                  injected_ids = []
                  replace_indices = []
                end
              else
                candidate_pool_count = cand_ct
                visible_pool_count = vis_ct
                final_ids = tmp_ids
                injected_ids = swapped_in_ids
              end
            else
              injected_ids, candidate_pool_count, visible_pool_count, watched_category_ids, watched_filter_applied =
                pick_random_promo_topic_ids(
                  user,
                  tag_id: tag_id,
                  exclude_ids: final_ids,
                  limit: replace_indices.length,
                  created_after: (created_after_last_digest_filter_applied ? last_digest_sent_at : nil)
                )

              if injected_ids.length == replace_indices.length
                replace_indices.each_with_index do |idx, j|
                  final_ids[idx] = injected_ids[j]
                end
              else
                injected_ids = []
                replace_indices = []
              end
            end
          end
        end
      end

      # ============================================================
      # Force first topic from watched categories (always evaluated)
      # ============================================================
      first_topic_id_before_force = (final_ids.present? ? final_ids.first.to_i : nil)
      first_topic_was_watched_before_force = first_topic_is_watched_category?(user, final_ids)

      before_force_first = final_ids
      final_ids = ensure_first_topic_from_watched_category(user, final_ids)
      forced_first_applied = (before_force_first != final_ids)

      first_topic_id_after_force = (final_ids.present? ? final_ids.first.to_i : nil)
      first_topic_was_watched_after_force = first_topic_is_watched_category?(user, final_ids)

      # Persist final digest topics ONLY if different (prevents double-log of same digest list)
      if final_ids.present? && final_ids != original_ids
        persist_last_digest_topics(user, final_ids)
      end

      # ============================================================
      # Async summary post (ALWAYS tries to enqueue)
      # ============================================================
      enqueue_summary_post(
        user: user,
        promo_tag: promo_tag,
        promo_tag_found: !tag_id.nil?,
        promo_tag_id: tag_id,
        promo_tag_total_topics: (tag_id ? count_all_topics_with_tag(tag_id) : 0),
        original_ids: original_ids,
        tagged_ids_in_original: original_ids.select { |tid| tagged_ids_set.include?(tid) },
        injected_ids: injected_ids,
        final_ids: final_ids,
        is_skipped_haspromo: is_skipped_haspromo,
        is_skipped_coinflip: is_skipped_coinflip,
        is_skipped_min_digests: is_skipped_min_digests,
        min_digests_required: min_digests_required,
        user_digest_count: user_digest_count_val,
        replaced_indices: replace_indices,
        attempted_replace: attempted_replace,
        candidate_pool_count: candidate_pool_count,
        visible_pool_count: visible_pool_count,
        watched_category_ids: watched_category_ids,
        watched_filter_applied: watched_filter_applied,
        forced_first_applied: forced_first_applied,
        first_topic_id_before_force: first_topic_id_before_force,
        first_topic_id_after_force: first_topic_id_after_force,
        first_topic_was_watched_before_force: first_topic_was_watched_before_force,
        first_topic_was_watched_after_force: first_topic_was_watched_after_force,
        last_digest_sent_at: last_digest_sent_at,
        created_after_last_digest_filter_enabled: created_after_last_digest_filter_enabled,
        created_after_last_digest_filter_applied: created_after_last_digest_filter_applied,
        promo_pick_mode: promo_pick_mode,
        digest_list_candidates_count: digest_list_candidates_count,
        digest_list_visible_count: digest_list_visible_count,
        digest_list_picked: digest_list_picked,
        fallback_picked: fallback_picked,
        used_fallback_outside_digest: used_fallback_outside_digest,
        user_watched_category_ids: user_watched_category_ids
      )

      # If nothing to order, keep original relation (report already enqueued)
      return original_relation if final_ids.blank?

      build_ordered_relation(user, final_ids)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] maybe_adjust_digest_topics error: #{e.class}: #{e.message}")
      original_relation
    end

    def self.extract_limit(opts)
      l = opts.is_a?(Hash) ? opts[:limit] : nil
      l = l.to_i if l
      l = ::PromoDigestConfig::DEFAULT_DIGEST_LIMIT if l.nil? || l <= 0
      l
    end

    # ---------- TAG HELPERS ----------
    def self.find_tag_by_name_ci(name)
      n = name.to_s.strip.downcase
      return nil if n.empty?
      Tag.where("LOWER(name) = ?", n).first
    end

    def self.count_all_topics_with_tag(tag_id)
      return 0 if tag_id.nil?
      TopicTag.where(tag_id: tag_id).count
    end

    def self.fetch_tagged_topic_ids(topic_ids, tag_id)
      return [] if topic_ids.blank?
      return [] if tag_id.nil?
      TopicTag.where(topic_id: topic_ids, tag_id: tag_id).pluck(:topic_id)
    end

    # ---------- WATCHED CATEGORY HELPERS ----------
    def self.watched_category_ids_for_user(user)
      return [] unless ::PromoDigestConfig::USE_WATCHED_CATEGORIES
      return [] if user.nil?

      levels = []
      if defined?(CategoryUser) && CategoryUser.respond_to?(:notification_levels)
        nl = CategoryUser.notification_levels
        levels << (nl[:watching] || 3)
        if ::PromoDigestConfig::INCLUDE_WATCHING_FIRST_POST
          levels << (nl[:watching_first_post] || 4)
        end
      else
        levels = ::PromoDigestConfig::INCLUDE_WATCHING_FIRST_POST ? [3, 4] : [3]
      end

      CategoryUser.where(user_id: user.id, notification_level: levels).pluck(:category_id)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] watched_category_ids_for_user failed: #{e.class}: #{e.message}")
      []
    end

    # ----------------------------
    # Ensure first digest topic is from a watched category (swap-based)
    # - honors FORCE_FIRST_TOPIC_WATCHED_COINFLIP_PERCENT
    # - NEW: if FORCE_FIRST_TOPIC_RANDOMIZE_EVEN_IF_ALREADY_WATCHED is true,
    #        we do not early-return when the first topic is already watched
    # - Selection: random among newest N watched-category topics in lookahead window
    # - if REQUIRE_CREATED_AFTER_LAST_DIGEST and last digest exists:
    #     * try candidates created after last digest (random among newest N)
    #     * if none and SOFT_FALLBACK => random among newest N watched-category candidates regardless
    # ----------------------------
    def self.ensure_first_topic_from_watched_category(user, ids)
      return ids if user.nil?
      return ids if ids.blank?
      return ids unless ::PromoDigestConfig::FORCE_FIRST_TOPIC_FROM_WATCHED_CATEGORY

      pct = ::PromoDigestConfig::FORCE_FIRST_TOPIC_WATCHED_COINFLIP_PERCENT.to_i
      pct = 0 if pct < 0
      pct = 100 if pct > 100
      return ids if pct == 0
      return ids if pct < 100 && rand(100) >= pct

      watched_ids = watched_category_ids_for_user(user)
      return ids if watched_ids.blank?

      guardian = Guardian.new(user)

      randomize_even_if_already_watched =
        (::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOMIZE_EVEN_IF_ALREADY_WATCHED == true)

      # If "randomize even if already watched" is OFF:
      # and first topic is already watched => DO NOTHING
      if !randomize_even_if_already_watched
        first_id = ids.first.to_i
        if first_id > 0
          first_cid =
            Topic
              .visible
              .secured(guardian)
              .where(id: first_id)
              .pluck(:category_id)
              .first

          return ids if first_cid.present? && watched_ids.include?(first_cid)
        end
      end

      lookahead = ::PromoDigestConfig::FORCE_FIRST_TOPIC_LOOKAHEAD.to_i
      lookahead = ids.length if lookahead <= 0
      window_ids = ids.first([lookahead, ids.length].min)

      # Pull id/category/created_at for candidates in window (secured)
      rows =
        Topic
          .visible
          .secured(guardian)
          .where(id: window_ids)
          .pluck(:id, :category_id, :created_at)

      return ids if rows.blank?

      watched_rows = rows.select { |_tid, cid, _created| cid && watched_ids.include?(cid) }
      return ids if watched_rows.blank?

      require_created_after = (::PromoDigestConfig::FORCE_FIRST_TOPIC_REQUIRE_CREATED_AFTER_LAST_DIGEST == true)
      soft_fallback = (::PromoDigestConfig::FORCE_FIRST_TOPIC_SOFT_FALLBACK == true)

      last_ts = nil
      if require_created_after
        last_ts = last_digest_sent_at_for_user(user)
      end

      top_n = ::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOM_TOP_N.to_i
      top_n = 5 if top_n <= 0

      # Sort newest first (created_at desc, then id desc)
      sort_newest_first = lambda do |arr|
        arr.sort_by do |tid, _cid, created|
          [-(created ? created.to_i : 0), -tid.to_i]
        end
      end

      pick_random_from_top = lambda do |arr|
        sorted = sort_newest_first.call(arr)
        top = sorted.first([top_n, sorted.length].min)
        top.sample
      end

      chosen = nil

      if require_created_after && last_ts.present?
        newer = watched_rows.select { |_tid, _cid, created| created.present? && created > last_ts }
        if newer.present?
          chosen = pick_random_from_top.call(newer)
        elsif soft_fallback
          chosen = pick_random_from_top.call(watched_rows)
        else
          return ids
        end
      else
        chosen = pick_random_from_top.call(watched_rows)
      end

      return ids if chosen.nil?
      chosen_id = chosen[0].to_i
      return ids if chosen_id <= 0

      return ids if ids.first.to_i == chosen_id

      new_ids = ids.dup
      chosen_idx = new_ids.index(chosen_id)
      return ids if chosen_idx.nil? || chosen_idx == 0

      new_ids[0], new_ids[chosen_idx] = new_ids[chosen_idx], new_ids[0]
      new_ids
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] ensure_first_topic_from_watched_category failed: #{e.class}: #{e.message}")
      ids
    end

    # ============================================================
    # Prefer-digest-list: eligible promo set inside digest list
    # ============================================================
    # Returns: [eligible_set, candidate_pool_count, visible_pool_count, watched_category_ids, watched_filter_applied]
    def self.eligible_promo_set_within_digest_list(user, tag_id:, digest_ids:, created_after: nil)
      return [Set.new, 0, 0, [], false] if user.nil?
      return [Set.new, 0, 0, [], false] if tag_id.nil?
      return [Set.new, 0, 0, [], false] if digest_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user(user)
      watched_filter_applied = watched_ids.present?

      scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_id, topic_id: digest_ids })

      scope = scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestConfig::FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST == true && created_after.present?
        scope = scope.where("topics.created_at > ?", created_after)
      end

      candidate_ids =
        scope
          .order(Arel.sql("RANDOM()"))
          .pluck("topic_tags.topic_id")

      candidate_pool_count = candidate_ids.length
      return [Set.new, candidate_pool_count, 0, watched_ids, watched_filter_applied] if candidate_ids.blank?

      visible_ids =
        Topic
          .visible
          .secured(guardian)
          .where(id: candidate_ids)
          .pluck(:id)

      visible_pool_count = visible_ids.length
      return [Set.new, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied] if visible_ids.blank?

      [visible_ids.to_set, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] eligible_promo_set_within_digest_list failed: #{e.class}: #{e.message}")
      [Set.new, 0, 0, [], false]
    end

    # ============================================================
    # Prefer-digest-list: swap eligible promos into target indices
    # ============================================================
    # Returns: [satisfied_indices, swapped_in_ids_for_targets, remaining_indices]
    def self.swap_eligible_promos_into_indices(ids, replace_indices, eligible_set)
      return [[], [], replace_indices] if ids.blank?
      idxs = Array(replace_indices).map(&:to_i).uniq
      return [[], [], []] if idxs.blank?
      return [[], [], idxs] if eligible_set.nil? || eligible_set.empty?

      satisfied = []
      swapped_in = []
      used_source_ids = Set.new

      idxs.each do |target_idx|
        next if target_idx < 0 || target_idx >= ids.length

        if eligible_set.include?(ids[target_idx])
          satisfied << target_idx
          swapped_in << ids[target_idx]
          next
        end

        pos = {}
        ids.each_with_index { |tid, i| pos[tid] = i }

        candidates = eligible_set.to_a.reject { |tid| used_source_ids.include?(tid) }
        candidates.select! { |tid| pos.key?(tid) && pos[tid] != target_idx }
        next if candidates.empty?

        target_set = idxs.to_set
        outside = candidates.select { |tid| !target_set.include?(pos[tid]) }
        pick_from = outside.any? ? outside : candidates

        chosen_id = pick_from.sample
        chosen_idx = pos[chosen_id]
        next if chosen_idx.nil? || chosen_idx == target_idx

        ids[target_idx], ids[chosen_idx] = ids[chosen_idx], ids[target_idx]

        used_source_ids.add(chosen_id)
        satisfied << target_idx
        swapped_in << chosen_id
      end

      remaining = idxs.reject { |i| satisfied.include?(i) }
      [satisfied, swapped_in, remaining]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] swap_eligible_promos_into_indices failed: #{e.class}: #{e.message}")
      [[], [], Array(replace_indices)]
    end

    # ============================================================
    # Global picker (forum-wide)
    # ============================================================
    # Returns [injected_ids, candidate_pool_count, visible_pool_count, watched_category_ids, watched_filter_applied]
    def self.pick_random_promo_topic_ids(user, tag_id:, exclude_ids:, limit:, created_after: nil)
      return [[], 0, 0, [], false] if limit.to_i <= 0
      return [[], 0, 0, [], false] if tag_id.nil?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user(user)
      watched_filter_applied = watched_ids.present?

      topic_tag_scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_id })
          .where.not(topic_tags: { topic_id: exclude_ids })

      topic_tag_scope = topic_tag_scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestConfig::FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST == true && created_after.present?
        topic_tag_scope = topic_tag_scope.where("topics.created_at > ?", created_after)
      end

      candidate_ids =
        topic_tag_scope
          .order(Arel.sql("RANDOM()"))
          .limit(10)
          .pluck("topic_tags.topic_id")

      candidate_pool_count = candidate_ids.length
      return [[], candidate_pool_count, 0, watched_ids, watched_filter_applied] if candidate_ids.blank?

      visible_scope =
        Topic
          .visible
          .secured(guardian)
          .where(id: candidate_ids)
          .where.not(id: exclude_ids)

      visible_scope = visible_scope.where(category_id: watched_ids) if watched_filter_applied

      visible_ids = visible_scope.pluck(:id)
      visible_pool_count = visible_ids.length
      return [[], candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied] if visible_ids.blank?

      injected_ids =
        visible_scope
          .order(Arel.sql("RANDOM()"))
          .limit(limit)
          .pluck(:id)

      [injected_ids, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] pick_random_promo_topic_ids failed: #{e.class}: #{e.message}")
      [[], 0, 0, [], false]
    end

    def self.build_ordered_relation(user, ids)
      return Topic.none if ids.blank?

      guardian = Guardian.new(user)

      case_sql = +"CASE topics.id "
      ids.each_with_index { |id, idx| case_sql << "WHEN #{id.to_i} THEN #{idx} " }
      case_sql << "END"

      Topic
        .visible
        .secured(guardian)
        .where(id: ids)
        .order(Arel.sql(case_sql))
    end

    # Robust URL builder (no Topic.slug_path dependency)
    def self.serialize_topics(ids)
      return [] if ids.blank?

      rows = Topic.where(id: ids).pluck(:id, :title, :slug, :category_id).map do |id, title, slug, category_id|
        slug_s = slug.to_s.strip
        path = slug_s.empty? ? "/t/#{id}" : "/t/#{slug_s}/#{id}"

        {
          id: id,
          title: title,
          slug: slug,
          category_id: category_id,
          url: "#{Discourse.base_url}#{path}"
        }
      end

      idx = {}
      ids.each_with_index { |tid, i| idx[tid] = i }
      rows.sort_by { |t| idx[t[:id]] || 999_999 }
    end

    def self.pack_topics(ids)
      return [] if ids.blank?
      return ids if ::PromoDigestConfig::SEND_IDS_ONLY
      serialize_topics(ids)
    end

    def self.enqueue_summary_post(
      user:,
      promo_tag:,
      promo_tag_found:,
      promo_tag_id:,
      promo_tag_total_topics:,
      original_ids:,
      tagged_ids_in_original:,
      injected_ids:,
      final_ids:,
      is_skipped_haspromo:,
      is_skipped_coinflip:,
      is_skipped_min_digests:,
      min_digests_required:,
      user_digest_count:,
      replaced_indices:,
      attempted_replace:,
      candidate_pool_count:,
      visible_pool_count:,
      watched_category_ids:,
      watched_filter_applied:,
      forced_first_applied:,
      first_topic_id_before_force:,
      first_topic_id_after_force:,
      first_topic_was_watched_before_force:,
      first_topic_was_watched_after_force:,
      last_digest_sent_at:,
      created_after_last_digest_filter_enabled:,
      created_after_last_digest_filter_applied:,
      promo_pick_mode:,
      digest_list_candidates_count:,
      digest_list_visible_count:,
      digest_list_picked:,
      fallback_picked:,
      used_fallback_outside_digest:,
      user_watched_category_ids:
    )
      endpoint = ::PromoDigestConfig::ENDPOINT_URL.to_s.strip
      return if endpoint.empty?

      now_iso = Time.now.utc.iso8601

      payload = {
        user_id: user.id,
        email: user.email,
        username: user.username,
        datetime_utc: now_iso,

        promo_tag: promo_tag,

        is_skipped_haspromo: is_skipped_haspromo,
        is_skipped_coinflip: is_skipped_coinflip,
        is_skipped_min_digests: is_skipped_min_digests,
        min_digests_required: min_digests_required,
        user_digest_count: user_digest_count,

        # NEW top-level fields for DB columns:
        forced_first_applied: forced_first_applied,
        first_topic_id_before_force: first_topic_id_before_force,
        first_topic_id_after_force: first_topic_id_after_force,
        first_topic_was_watched_before_force: first_topic_was_watched_before_force,
        first_topic_was_watched_after_force: first_topic_was_watched_after_force,

        original_topics: pack_topics(original_ids),
        tagged_topics_in_original: pack_topics(tagged_ids_in_original),

        injected_topics: pack_topics(injected_ids),
        final_topics: pack_topics(final_ids),

        debug: {
          promo_tag_found: promo_tag_found,
          promo_tag_id: promo_tag_id,
          promo_tag_total_topics: promo_tag_total_topics,

          attempted_replace: attempted_replace,
          candidate_pool_count: candidate_pool_count,
          visible_pool_count: visible_pool_count,

          # clarity: always include the user's watched categories, even if promo injection was skipped
          user_watched_category_ids: user_watched_category_ids,

          watched_category_ids: watched_category_ids,
          watched_categories_mode: ::PromoDigestConfig::USE_WATCHED_CATEGORIES,
          watched_filter_applied: watched_filter_applied,

          forced_first_topic_from_watched_category_enabled: ::PromoDigestConfig::FORCE_FIRST_TOPIC_FROM_WATCHED_CATEGORY,
          forced_first_topic_coinflip_percent: ::PromoDigestConfig::FORCE_FIRST_TOPIC_WATCHED_COINFLIP_PERCENT,
          force_first_topic_randomize_even_if_already_watched: ::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOMIZE_EVEN_IF_ALREADY_WATCHED,
          force_first_topic_random_top_n: ::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOM_TOP_N,
          forced_first_topic_require_created_after_last_digest: ::PromoDigestConfig::FORCE_FIRST_TOPIC_REQUIRE_CREATED_AFTER_LAST_DIGEST,
          forced_first_topic_soft_fallback: ::PromoDigestConfig::FORCE_FIRST_TOPIC_SOFT_FALLBACK,
          forced_first_topic_applied: forced_first_applied,

          first_topic_id_before_force: first_topic_id_before_force,
          first_topic_id_after_force: first_topic_id_after_force,
          first_topic_was_watched_before_force: first_topic_was_watched_before_force,
          first_topic_was_watched_after_force: first_topic_was_watched_after_force,

          created_after_last_digest_filter_enabled: created_after_last_digest_filter_enabled,
          created_after_last_digest_filter_applied: created_after_last_digest_filter_applied,
          last_digest_sent_at_utc: (last_digest_sent_at.present? ? last_digest_sent_at.utc.iso8601 : nil),

          promo_pick_mode: promo_pick_mode,
          digest_list_candidates_count: digest_list_candidates_count,
          digest_list_visible_count: digest_list_visible_count,
          digest_list_picked: digest_list_picked,
          used_fallback_outside_digest: used_fallback_outside_digest,
          fallback_picked: fallback_picked,

          injected_topic_ids: injected_ids,
          replaced_indices: replaced_indices
        }
      }

      Jobs.enqueue(
        :promo_digest_send_summary,
        endpoint_url: ::PromoDigestConfig::ENDPOINT_URL,
        secret: ::PromoDigestConfig::SECRET_HEADER_VALUE,
        log_post_results: ::PromoDigestConfig::LOG_POST_RESULTS,
        open_timeout: ::PromoDigestConfig::HTTP_OPEN_TIMEOUT,
        read_timeout: ::PromoDigestConfig::HTTP_READ_TIMEOUT,
        payload_json: payload.to_json
      )
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] enqueue summary POST failed: #{e.class}: #{e.message}")
    end
  end

  # Run only while digest is being generated
  module ::PromoDigestDigestWrapper
    def digest(user, opts = {})
      Thread.current[:promo_digest_in_digest] = true
      super
    ensure
      Thread.current[:promo_digest_in_digest] = false
    end
  end
  ::UserNotifications.prepend ::PromoDigestDigestWrapper

  # Intercept Topic.for_digest(user, since, opts=nil)
  module ::PromoDigestForDigestOverride
    def for_digest(user, since, opts = nil)
      rel = super(user, since, opts)
      ::PromoDigestInjector.maybe_adjust_digest_topics(user, rel, opts)
    end
  end
  ::Topic.singleton_class.prepend ::PromoDigestForDigestOverride
end
