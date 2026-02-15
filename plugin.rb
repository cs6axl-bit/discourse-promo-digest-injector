# frozen_string_literal: true
# name: discourse-promo-digest-injector
# about: Ensures digest includes tag-marked topics near the top (with optional random injection) and posts a run summary to an external endpoint (async, non-blocking). Optionally restricts promo picks to categories the user is "watching". Also (A) requires a minimum number of digests before injecting and (B) stores last 50 FINAL digest topic IDs per user (newest digest first, duplicates allowed). Stores last 10 FINAL position-0 topic IDs per user (newest first, duplicates allowed). If user has NO watched categories, can optionally shuffle the first N digest topics. If first topic is promo, forced-first swapping prefers promo-only candidates (fallback to any watched). Enforce min % of watched-category topics in digest list. DEBUG: adds digest_build_uuid + for_digest_call_index + since/opts/callsite into debug payload. FIX: only inject/log for the REAL digest for_digest call (opts[:top_order]==true + opts[:limit] present), skipping Post.for_mailing_list calls etc.
# version: 1.3.9
# authors: you

after_initialize do
  require "net/http"
  require "uri"
  require "json"
  require "set"
  require "time"
  require "securerandom"

  PLUGIN_NAME = "discourse-promo-digest-injector"

  # ============================================================
  # CONFIG (EDIT HERE)
  # ============================================================
  module ::PromoDigestConfig
    ENABLED = true

    # Don't activate promo insertion logic until user has received at least this many digests
    MIN_DIGESTS_BEFORE_INJECT = 3

    # If you run the digest counter plugin, it stores digest count here (fast path):
    DIGEST_COUNT_CUSTOM_FIELD = "digest_sent_counter"

    # PROMO SOURCE: Tag names on topics (case-insensitive)
    PROMO_TAGS = ["helpful", "useful"]

    # If user is "watching" any categories, only pick promo-tagged topics from those categories.
    USE_WATCHED_CATEGORIES = true
    INCLUDE_WATCHING_FIRST_POST = true # treat "watching first post" as watched too

    # If ANY promo-tagged topic exists in positions 1..MIN_POSITION => do nothing
    # UPDATED: if user watches categories, this check uses (tag AND watched category) else tag-only.
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

    # ============================================================
    # PERSISTED HISTORY (FINAL DIGEST CONTENTS)
    # ============================================================
    LAST_DIGEST_TOPICS_FIELD = "promo_digest_last50_topic_ids" # JSON array of ints (string)
    LAST_DIGEST_TOPICS_MAX   = 50

    LAST_DIGEST_FIRST_TOPICS_FIELD = "promo_digest_last10_first_topic_ids" # JSON array of ints (string)
    LAST_DIGEST_FIRST_TOPICS_MAX   = 10

    # ============================================================
    # Force first topic logic
    # ============================================================
    FORCE_FIRST_TOPIC_FROM_WATCHED_CATEGORY = true
    FORCE_FIRST_TOPIC_WATCHED_COINFLIP_PERCENT = 100 # 0..100
    FORCE_FIRST_TOPIC_RANDOMIZE_EVEN_IF_ALREADY_WATCHED = true
    FORCE_FIRST_TOPIC_RANDOM_TOP_N = 5
    FORCE_FIRST_TOPIC_REQUIRE_CREATED_AFTER_LAST_DIGEST = true
    FORCE_FIRST_TOPIC_SOFT_FALLBACK = true
    FORCE_FIRST_TOPIC_LOOKAHEAD = 50

    # Promo pool recency gate:
    FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST = true

    # ============================================================
    # NO-WATCHED-CATEGORIES SHUFFLE
    # ============================================================
    SHUFFLE_TOPICS_IF_NO_WATCHED_CATEGORIES = true
    SHUFFLE_TOPICS_IF_NO_WATCHED_TOP_N      = 4
    SHUFFLE_TOPICS_IF_NO_WATCHED_COINFLIP_PERCENT = 100 # 0..100

    # ============================================================
    # PROMO PICK STRATEGY SWITCH
    # ============================================================
    PROMO_PICK_MODE = "prefer_digest_list" # "global" or "prefer_digest_list"
    PROMO_CANDIDATE_SCAN_CAP = 500

    # ============================================================
    # WATCHED-CATEGORY PERCENT ENFORCER
    # ============================================================
    ENFORCE_MIN_WATCHED_CATEGORY_PERCENT = true
    MIN_WATCHED_CATEGORY_PERCENT         = 50 # 0..100
    WATCHED_ENFORCE_LOOKAHEAD_EXTRA      = 100
    WATCHED_ENFORCE_FORUM_SCAN_CAP       = 500

    # ============================================================
    # SUPERPROMO (INDEPENDENT SECOND PIPELINE)
    # Runs AFTER regular promo injection
    # ============================================================
    SUPERPROMO_ENABLED = false

    # Tag names on topics (case-insensitive) for superpromo pipeline
    SUPERPROMO_TAGS = ["trusted"]

    # If user is "watching" any categories, only pick superpromo-tagged topics from those categories.
    SUPERPROMO_USE_WATCHED_CATEGORIES = true
    SUPERPROMO_INCLUDE_WATCHING_FIRST_POST = true

    # If ANY superpromo-tagged topic exists in positions 1..SUPERPROMO_MIN_POSITION => do nothing
    SUPERPROMO_MIN_POSITION = 3

    # If above condition fails: in this % of cases do nothing
    SUPERPROMO_COINFLIP_SKIP_PERCENT = 30 # 0..100

    # Otherwise: replace SUPERPROMO_REPLACE_COUNT topics within the top SUPERPROMO_REPLACE_WITHIN_TOP_N positions
    SUPERPROMO_REPLACE_WITHIN_TOP_N = 3
    SUPERPROMO_REPLACE_COUNT        = 1

    # Superpromo pool recency gate:
    SUPERPROMO_FILTER_TOPICS_CREATED_AFTER_LAST_DIGEST = true

    # Pick strategy:
    SUPERPROMO_PICK_MODE = "prefer_digest_list" # "global" or "prefer_digest_list"
    SUPERPROMO_CANDIDATE_SCAN_CAP = 500

    # ============================================================
    # DEBUG HELPERS
    # ============================================================
    DEBUG_CALLSITE_DEPTH = 10
    DEBUG_INCLUDE_OPTS = true
  end

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
    # Last digest sent timestamp
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
    # Store last 50 FINAL digest topics (newest first, duplicates allowed)
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
    # Store last 10 FINAL position-0 topic ids (newest first, duplicates allowed)
    # ----------------------------
    def self.persist_last_digest_first_topic(user, first_topic_id)
      return if user.nil?

      field = ::PromoDigestConfig::LAST_DIGEST_FIRST_TOPICS_FIELD.to_s
      return if field.strip.empty?

      max_n = ::PromoDigestConfig::LAST_DIGEST_FIRST_TOPICS_MAX.to_i
      max_n = 10 if max_n <= 0

      tid = first_topic_id.to_i
      return if tid <= 0

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

        combined = ([tid] + prev).first(max_n)

        u.custom_fields[field] = combined.to_json
        u.save_custom_fields(true)
      end
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] persist_last_digest_first_topic failed: #{e.class}: #{e.message}")
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
    # helper: does a topic have ANY of the given tags?
    # ----------------------------
    def self.topic_has_any_tag?(topic_id, tag_ids)
      tid = topic_id.to_i
      ids = Array(tag_ids).map(&:to_i).reject(&:zero?).uniq
      return false if tid <= 0 || ids.blank?

      TopicTag.where(topic_id: tid, tag_id: ids).limit(1).exists?
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] topic_has_any_tag? failed: #{e.class}: #{e.message}")
      false
    end

    # ============================================================
    # Watched-category percent enforcer
    # ============================================================
    def self.enforce_min_watched_category_percent(user, ids, base_relation, limit:, last_digest_sent_at:)
      return [ids, false, {}, []] if user.nil?
      return [ids, false, {}, []] if ids.blank?
      return [ids, false, {}, []] unless ::PromoDigestConfig::ENFORCE_MIN_WATCHED_CATEGORY_PERCENT == true

      watched_ids = watched_category_ids_for_user(user)
      return [ids, false, {}, watched_ids] if watched_ids.blank?

      pct = ::PromoDigestConfig::MIN_WATCHED_CATEGORY_PERCENT.to_i
      pct = 0 if pct < 0
      pct = 100 if pct > 100
      return [ids, false, {}, watched_ids] if pct <= 0

      guardian = Guardian.new(user)

      rows = Topic.visible.secured(guardian).where(id: ids).pluck(:id, :category_id)
      tid_to_cid = {}
      rows.each { |tid, cid| tid_to_cid[tid.to_i] = cid.to_i if tid && cid }

      total = ids.length
      target_count = ((total * pct) / 100.0).ceil

      current_watched_count =
        ids.count do |tid|
          cid = tid_to_cid[tid.to_i]
          cid && watched_ids.include?(cid)
        end

      debug = {
        enabled: true,
        min_percent: pct,
        total_topics: total,
        target_watched_count: target_count,
        watched_count_before: current_watched_count,
        watched_count_after: current_watched_count,
        replaced_positions: [],
        replaced_out_ids: [],
        replaced_in_ids: [],
        replaced_source: [] # "lookahead" or "forum"
      }

      return [ids, false, debug, watched_ids] if current_watched_count >= target_count

      need = target_count - current_watched_count
      new_ids = ids.dup

      replace_positions = []
      new_ids.each_with_index do |tid, idx|
        cid = tid_to_cid[tid.to_i]
        is_watched = (cid && watched_ids.include?(cid))
        replace_positions << idx unless is_watched
      end
      return [ids, false, debug, watched_ids] if replace_positions.blank?

      # Step 1: digest lookahead
      lookahead_extra = ::PromoDigestConfig::WATCHED_ENFORCE_LOOKAHEAD_EXTRA.to_i
      lookahead_extra = 0 if lookahead_extra < 0

      if lookahead_extra > 0 && base_relation.present?
        extra_ids =
          base_relation
            .limit(limit.to_i + lookahead_extra)
            .pluck(:id)
            .map(&:to_i)

        extra_ids = extra_ids.drop(limit.to_i)
        extra_ids = extra_ids.reject(&:zero?)
        extra_ids = extra_ids - new_ids

        if extra_ids.present?
          extra_visible =
            Topic
              .visible
              .secured(guardian)
              .where(id: extra_ids, category_id: watched_ids)
              .pluck(:id)
              .map(&:to_i)

          if extra_visible.present?
            extra_visible_sorted =
              Topic
                .visible
                .secured(guardian)
                .where(id: extra_visible)
                .order(created_at: :desc, id: :desc)
                .pluck(:id)
                .map(&:to_i)

            extra_visible_sorted.each do |cand_id|
              break if need <= 0
              break if replace_positions.empty?

              pos = replace_positions.shift
              out_id = new_ids[pos]
              new_ids[pos] = cand_id

              debug[:replaced_positions] << pos
              debug[:replaced_out_ids] << out_id
              debug[:replaced_in_ids] << cand_id
              debug[:replaced_source] << "lookahead"

              need -= 1
            end
          end
        end
      end

      # Step 2: forum-wide watched categories, created_after_last_digest if known
      if need > 0 && replace_positions.present?
        scan_cap = ::PromoDigestConfig::WATCHED_ENFORCE_FORUM_SCAN_CAP.to_i
        scan_cap = 500 if scan_cap <= 0

        scope =
          Topic
            .visible
            .secured(guardian)
            .where(category_id: watched_ids)
            .where.not(id: new_ids)

        scope = scope.where("topics.created_at > ?", last_digest_sent_at) if last_digest_sent_at.present?

        forum_candidates =
          scope
            .order(created_at: :desc, id: :desc)
            .limit(scan_cap)
            .pluck(:id)
            .map(&:to_i)

        forum_candidates.each do |cand_id|
          break if need <= 0
          break if replace_positions.empty?

          pos = replace_positions.shift
          out_id = new_ids[pos]
          new_ids[pos] = cand_id

          debug[:replaced_positions] << pos
          debug[:replaced_out_ids] << out_id
          debug[:replaced_in_ids] << cand_id
          debug[:replaced_source] << "forum"

          need -= 1
        end
      end

      rows2 = Topic.visible.secured(guardian).where(id: new_ids).pluck(:id, :category_id)
      tid_to_cid2 = {}
      rows2.each { |tid, cid| tid_to_cid2[tid.to_i] = cid.to_i if tid && cid }

      watched_after =
        new_ids.count do |tid|
          cid = tid_to_cid2[tid.to_i]
          cid && watched_ids.include?(cid)
        end

      debug[:watched_count_after] = watched_after
      applied = (new_ids != ids)

      [new_ids, applied, debug, watched_ids]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] enforce_min_watched_category_percent failed: #{e.class}: #{e.message}")
      [ids, false, {}, watched_category_ids_for_user(user)]
    end

    # ----------------------------
    # DEBUG: sanitize opts
    # ----------------------------
    def self.sanitize_opts_for_debug(opts)
      return nil unless ::PromoDigestConfig::DEBUG_INCLUDE_OPTS == true
      return nil unless opts.is_a?(Hash)

      out = {}
      opts.each do |k, v|
        key = k.to_s
        case v
        when String, Integer, Float, TrueClass, FalseClass, NilClass
          out[key] = v
        when Time
          out[key] = v.utc.iso8601
        else
          out[key] = v.class.name
        end
      end
      out
    rescue
      nil
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

      promo_tags =
        Array(::PromoDigestConfig::PROMO_TAGS)
          .map { |t| t.to_s.strip.downcase }
          .reject(&:empty?)
          .uniq

      promo_tag_for_payload = promo_tags.join(", ")

      tags = promo_tags.map { |t| find_tag_by_name_ci(t) }.compact
      tag_ids = tags.map(&:id).compact.uniq

      # SUPERPROMO tags (independent pipeline)
      superpromo_tags =
        Array(::PromoDigestConfig::SUPERPROMO_TAGS)
          .map { |t| t.to_s.strip.downcase }
          .reject(&:empty?)
          .uniq

      superpromo_tag_for_payload = superpromo_tags.join(", ")
      superpromo_tag_models = superpromo_tags.map { |t| find_tag_by_name_ci(t) }.compact
      superpromo_tag_ids = superpromo_tag_models.map(&:id).compact.uniq

      user_watched_category_ids = watched_category_ids_for_user(user)

      # ---------- DEBUG CONTEXT ----------
      digest_build_uuid = Thread.current[:promo_digest_build_uuid]
      for_digest_call_index = Thread.current[:promo_digest_for_digest_call_index]
      for_digest_since = Thread.current[:promo_digest_since]
      for_digest_opts_sanitized = Thread.current[:promo_digest_opts_sanitized]
      for_digest_callsite = Thread.current[:promo_digest_callsite]

      since_key = for_digest_since.respond_to?(:to_i) ? for_digest_since.to_i : 0
      debug_dedupe_key = "u#{user.id}-s#{since_key}-l#{limit}"

      # ---------- GATE: do not return early; mark skipped + ALWAYS send report ----------
      min_digests_required = ::PromoDigestConfig::MIN_DIGESTS_BEFORE_INJECT.to_i
      min_digests_required = 0 if min_digests_required < 0

      user_digest_count_val = 0
      is_skipped_min_digests = false
      if min_digests_required > 0
        user_digest_count_val = user_digest_count(user)
        is_skipped_min_digests = (user_digest_count_val < min_digests_required)
      end

      tagged_ids_set =
        if original_ids.present? && tag_ids.present?
          if user_watched_category_ids.present?
            fetch_tagged_topic_ids_any_tag_in_categories(original_ids, tag_ids, user_watched_category_ids).to_set
          else
            fetch_tagged_topic_ids_any_tag(original_ids, tag_ids).to_set
          end
        else
          Set.new
        end

      tagged_ids_in_original =
        if original_ids.present? && tagged_ids_set.present?
          original_ids.select { |tid| tagged_ids_set.include?(tid) }
        else
          []
        end

      original_topics_matched_tags =
        matched_promo_tag_names_by_topic(tagged_ids_in_original, promo_tags)

      min_position = ::PromoDigestConfig::MIN_POSITION.to_i
      min_position = 3 if min_position <= 0

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

      last_digest_sent_at = last_digest_sent_at_for_user(user)
      created_after_last_digest_filter_enabled = (::PromoDigestConfig::FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST == true)
      created_after_last_digest_filter_applied = (created_after_last_digest_filter_enabled && last_digest_sent_at.present?)

      promo_pick_mode = ::PromoDigestConfig::PROMO_PICK_MODE.to_s.strip
      promo_pick_mode = "global" if promo_pick_mode.empty?
      prefer_digest_list_mode = (promo_pick_mode == "prefer_digest_list")

      digest_list_candidates_count = 0
      digest_list_visible_count = 0
      digest_list_picked = []
      fallback_picked = []
      used_fallback_outside_digest = false

      no_watched_shuffle_enabled = (::PromoDigestConfig::SHUFFLE_TOPICS_IF_NO_WATCHED_CATEGORIES == true)
      no_watched_shuffle_top_n   = ::PromoDigestConfig::SHUFFLE_TOPICS_IF_NO_WATCHED_TOP_N.to_i
      no_watched_shuffle_top_n   = 4 if no_watched_shuffle_top_n <= 0
      no_watched_shuffle_coinflip_percent = ::PromoDigestConfig::SHUFFLE_TOPICS_IF_NO_WATCHED_COINFLIP_PERCENT.to_i
      no_watched_shuffle_coinflip_percent = 0 if no_watched_shuffle_coinflip_percent < 0
      no_watched_shuffle_coinflip_percent = 100 if no_watched_shuffle_coinflip_percent > 100
      no_watched_shuffle_applied = false

      watched_percent_enforcer_applied = false
      watched_percent_debug = {}

      # -------- SUPERPROMO tracking vars --------
      superpromo_has_tagged_in_top = false
      superpromo_is_skipped_hastag = false
      superpromo_is_skipped_coinflip = false
      superpromo_attempted_replace = false
      superpromo_replace_indices = []
      superpromo_injected_ids = []

      superpromo_candidate_pool_count = 0
      superpromo_visible_pool_count = 0
      superpromo_watched_category_ids = []
      superpromo_watched_filter_applied = false

      superpromo_pick_mode = ::PromoDigestConfig::SUPERPROMO_PICK_MODE.to_s.strip
      superpromo_pick_mode = "global" if superpromo_pick_mode.empty?
      superpromo_prefer_digest_list_mode = (superpromo_pick_mode == "prefer_digest_list")

      superpromo_digest_list_candidates_count = 0
      superpromo_digest_list_visible_count = 0
      superpromo_digest_list_picked = []
      superpromo_fallback_picked = []
      superpromo_used_fallback_outside_digest = false

      superpromo_created_after_enabled = (::PromoDigestConfig::SUPERPROMO_FILTER_TOPICS_CREATED_AFTER_LAST_DIGEST == true)
      superpromo_created_after_applied = (superpromo_created_after_enabled && last_digest_sent_at.present?)

      # ============================================================
      # Promo injection block (blocked by min-digests gate)
      # ============================================================
      if !is_skipped_min_digests && !is_skipped_haspromo && original_ids.present? && tag_ids.present?
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
                  tag_ids: tag_ids,
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
                    tag_ids: tag_ids,
                    exclude_ids: original_ids,
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
                  tag_ids: tag_ids,
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
      # SUPERPROMO injection block (runs SECOND, independent)
      # ============================================================
   if ::PromoDigestConfig::SUPERPROMO_ENABLED == true &&
   !is_skipped_min_digests &&
   final_ids.present? &&
   superpromo_tag_ids.present?

        # Determine whether there is already a superpromo tag in top N (using superpromo watched settings)
        superpromo_tagged_ids_set =
          begin
            w2 = watched_category_ids_for_user_superpromo(user)
            if w2.present?
              fetch_tagged_topic_ids_any_tag_in_categories(final_ids, superpromo_tag_ids, w2).to_set
            else
              fetch_tagged_topic_ids_any_tag(final_ids, superpromo_tag_ids).to_set
            end
          rescue
            Set.new
          end

        superpromo_min_position = ::PromoDigestConfig::SUPERPROMO_MIN_POSITION.to_i
        superpromo_min_position = 3 if superpromo_min_position <= 0

        superpromo_has_tagged_in_top =
          if final_ids.present?
            final_ids.first(superpromo_min_position).any? { |tid| superpromo_tagged_ids_set.include?(tid) }
          else
            false
          end

        superpromo_is_skipped_hastag = superpromo_has_tagged_in_top

        superpromo_skip_percent = ::PromoDigestConfig::SUPERPROMO_COINFLIP_SKIP_PERCENT.to_i
        superpromo_skip_percent = 0 if superpromo_skip_percent < 0
        superpromo_skip_percent = 100 if superpromo_skip_percent > 100

        if !superpromo_is_skipped_hastag
          if rand(100) < superpromo_skip_percent
            superpromo_is_skipped_coinflip = true
          else
            within_top_n = ::PromoDigestConfig::SUPERPROMO_REPLACE_WITHIN_TOP_N.to_i
            within_top_n = 3 if within_top_n <= 0

            sp_replace_count = ::PromoDigestConfig::SUPERPROMO_REPLACE_COUNT.to_i
            sp_replace_count = 1 if sp_replace_count <= 0

            window = [within_top_n, final_ids.length].min
            if window > 0 && sp_replace_count > 0
              superpromo_attempted_replace = true
              superpromo_replace_indices = (0...window).to_a.sample([sp_replace_count, window].min)

              if superpromo_prefer_digest_list_mode
                tmp_ids = final_ids.dup

                eligible_set, cand_ct, vis_ct, watched_ids, watched_applied =
                  eligible_superpromo_set_within_digest_list(
                    user,
                    tag_ids: superpromo_tag_ids,
                    digest_ids: final_ids, # IMPORTANT: operate on post-promo list
                    created_after: (superpromo_created_after_applied ? last_digest_sent_at : nil)
                  )

                superpromo_digest_list_candidates_count = cand_ct
                superpromo_digest_list_visible_count = vis_ct
                superpromo_watched_category_ids = watched_ids
                superpromo_watched_filter_applied = watched_applied

                _satisfied, swapped_in_ids, remaining_indices =
                  swap_eligible_promos_into_indices(
                    tmp_ids,
                    superpromo_replace_indices,
                    eligible_set
                  )

                superpromo_digest_list_picked = swapped_in_ids.dup

                if remaining_indices.any?
                  remaining_need = remaining_indices.length

                  fallback_ids, cand_b, vis_b, watched_b, watched_applied_b =
                    pick_random_superpromo_topic_ids(
                      user,
                      tag_ids: superpromo_tag_ids,
                      exclude_ids: tmp_ids,
                      limit: remaining_need,
                      created_after: (superpromo_created_after_applied ? last_digest_sent_at : nil)
                    )

                  superpromo_used_fallback_outside_digest = fallback_ids.present?
                  superpromo_fallback_picked = fallback_ids.dup

                  superpromo_candidate_pool_count = cand_ct + cand_b
                  superpromo_visible_pool_count = vis_ct + vis_b

                  superpromo_watched_category_ids = watched_b
                  superpromo_watched_filter_applied = watched_applied_b

                  if fallback_ids.length == remaining_need
                    remaining_indices.each_with_index do |idx, j|
                      tmp_ids[idx] = fallback_ids[j]
                    end

                    final_ids = tmp_ids
                    superpromo_injected_ids = swapped_in_ids + fallback_ids
                  else
                    superpromo_injected_ids = []
                    superpromo_replace_indices = []
                  end
                else
                  superpromo_candidate_pool_count = cand_ct
                  superpromo_visible_pool_count = vis_ct
                  final_ids = tmp_ids
                  superpromo_injected_ids = swapped_in_ids
                end
              else
                superpromo_injected_ids, superpromo_candidate_pool_count, superpromo_visible_pool_count,
                  superpromo_watched_category_ids, superpromo_watched_filter_applied =
                    pick_random_superpromo_topic_ids(
                      user,
                      tag_ids: superpromo_tag_ids,
                      exclude_ids: final_ids,
                      limit: superpromo_replace_indices.length,
                      created_after: (superpromo_created_after_applied ? last_digest_sent_at : nil)
                    )

                if superpromo_injected_ids.length == superpromo_replace_indices.length
                  superpromo_replace_indices.each_with_index do |idx, j|
                    final_ids[idx] = superpromo_injected_ids[j]
                  end
                else
                  superpromo_injected_ids = []
                  superpromo_replace_indices = []
                end
              end
            end
          end
        end
      end

      # ============================================================
      # Enforce minimum % watched-category topics (AFTER promo+superpromo, BEFORE first-topic logic)
      # ============================================================
      begin
        final_ids, watched_percent_enforcer_applied, watched_percent_debug, _ =
          enforce_min_watched_category_percent(
            user,
            final_ids,
            original_relation,
            limit: limit,
            last_digest_sent_at: last_digest_sent_at
          )
      rescue => e
        Rails.logger.warn("[#{PLUGIN_NAME}] watched-percent enforcer wrapper failed: #{e.class}: #{e.message}")
      end

      # ============================================================
      # Force first topic from watched categories (always evaluated)
      # ============================================================
      first_topic_id_before_force = (final_ids.present? ? final_ids.first.to_i : nil)
      first_topic_was_watched_before_force = first_topic_is_watched_category?(user, final_ids)

      before_force_first = final_ids

      if user_watched_category_ids.blank? && no_watched_shuffle_enabled && no_watched_shuffle_coinflip_percent > 0
        if (no_watched_shuffle_coinflip_percent >= 100) || (rand(100) < no_watched_shuffle_coinflip_percent)
          n = [no_watched_shuffle_top_n, final_ids.length].min
          if n >= 2
            shuffled = final_ids.first(n).shuffle
            final_ids = shuffled + final_ids.drop(n)
            no_watched_shuffle_applied = (final_ids != before_force_first)
          end
        end
      else
        first_is_promo = false
        if final_ids.present? && tag_ids.present?
          first_is_promo = topic_has_any_tag?(final_ids.first, tag_ids)
        end

        final_ids =
          ensure_first_topic_from_watched_category(
            user,
            final_ids,
            promo_tag_ids: tag_ids,
            prefer_promo_only_if_first_is_promo: first_is_promo
          )
      end

      forced_first_applied = (before_force_first != final_ids)

      first_topic_id_after_force = (final_ids.present? ? final_ids.first.to_i : nil)
      first_topic_was_watched_after_force = first_topic_is_watched_category?(user, final_ids)

      injected_topics_matched_tags =
        matched_promo_tag_names_by_topic(injected_ids, promo_tags)

      first_injected_tag_name =
        if injected_ids.present?
          Array(injected_topics_matched_tags[injected_ids.first.to_i]).first
        else
          nil
        end

      # ============================================================
      # PERSIST FINAL DIGEST CONTENTS
      # ============================================================
      if final_ids.present?
        persist_last_digest_topics(user, final_ids)
        persist_last_digest_first_topic(user, final_ids.first)
      end

      enqueue_summary_post(
        user: user,
        promo_tag: promo_tag_for_payload,
        promo_tag_found: tag_ids.present?,
        promo_tag_id: (tag_ids.present? ? tag_ids.first : nil),
        promo_tag_total_topics: (tag_ids.present? ? count_all_topics_with_any_tag(tag_ids) : 0),
        promo_tag_ids: tag_ids,
        promo_tag_names: promo_tags,
        first_injected_tag_name: first_injected_tag_name,

        original_ids: original_ids,
        tagged_ids_in_original: tagged_ids_in_original,
        injected_ids: injected_ids,
        final_ids: final_ids,

        original_topics_matched_tags: original_topics_matched_tags,
        injected_topics_matched_tags: injected_topics_matched_tags,

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
        user_watched_category_ids: user_watched_category_ids,

        no_watched_shuffle_enabled: no_watched_shuffle_enabled,
        no_watched_shuffle_applied: no_watched_shuffle_applied,
        no_watched_shuffle_top_n: no_watched_shuffle_top_n,
        no_watched_shuffle_coinflip_percent: no_watched_shuffle_coinflip_percent,

        watched_percent_enforcer_applied: watched_percent_enforcer_applied,
        watched_percent_debug: watched_percent_debug,

        # -------- SUPERPROMO DEBUG --------
        superpromo_tag: superpromo_tag_for_payload,
        superpromo_tag_ids: superpromo_tag_ids,
        superpromo_injected_ids: superpromo_injected_ids,
        superpromo_attempted_replace: superpromo_attempted_replace,
        superpromo_replace_indices: superpromo_replace_indices,
        superpromo_is_skipped_hastag: superpromo_is_skipped_hastag,
        superpromo_is_skipped_coinflip: superpromo_is_skipped_coinflip,
        superpromo_candidate_pool_count: superpromo_candidate_pool_count,
        superpromo_visible_pool_count: superpromo_visible_pool_count,
        superpromo_watched_category_ids: superpromo_watched_category_ids,
        superpromo_watched_filter_applied: superpromo_watched_filter_applied,
        superpromo_pick_mode: superpromo_pick_mode,
        superpromo_digest_list_candidates_count: superpromo_digest_list_candidates_count,
        superpromo_digest_list_visible_count: superpromo_digest_list_visible_count,
        superpromo_digest_list_picked: superpromo_digest_list_picked,
        superpromo_fallback_picked: superpromo_fallback_picked,
        superpromo_used_fallback_outside_digest: superpromo_used_fallback_outside_digest,
        superpromo_created_after_enabled: superpromo_created_after_enabled,
        superpromo_created_after_applied: superpromo_created_after_applied,

        # -------- DEBUG --------
        debug_digest_build_uuid: digest_build_uuid,
        debug_for_digest_call_index: for_digest_call_index,
        debug_for_digest_since: (for_digest_since.respond_to?(:utc) ? for_digest_since.utc.iso8601 : for_digest_since),
        debug_for_digest_opts: for_digest_opts_sanitized,
        debug_for_digest_callsite: for_digest_callsite,
        debug_dedupe_key: debug_dedupe_key
      )

      return original_relation if final_ids.blank?
      build_ordered_relation(user, final_ids)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] maybe_adjust_digest_topics error: #{e.class}: #{e.message}")
      original_relation
    end

    def self.extract_limit(opts)
      l = opts.is_a?(Hash) ? (opts[:limit] || opts["limit"]) : nil
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

    def self.count_all_topics_with_any_tag(tag_ids)
      return 0 if tag_ids.blank?
      TopicTag.where(tag_id: tag_ids).distinct.count(:topic_id)
    end

    def self.fetch_tagged_topic_ids_any_tag(topic_ids, tag_ids)
      return [] if topic_ids.blank?
      return [] if tag_ids.blank?
      TopicTag.where(topic_id: topic_ids, tag_id: tag_ids).distinct.pluck(:topic_id)
    end

    def self.fetch_tagged_topic_ids_any_tag_in_categories(topic_ids, tag_ids, category_ids)
      return [] if topic_ids.blank?
      return [] if tag_ids.blank?
      cids = Array(category_ids).map(&:to_i).reject(&:zero?).uniq
      return [] if cids.blank?

      TopicTag
        .joins(:topic)
        .where(topic_tags: { topic_id: topic_ids, tag_id: tag_ids })
        .where(topics: { category_id: cids })
        .distinct
        .pluck("topic_tags.topic_id")
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] fetch_tagged_topic_ids_any_tag_in_categories failed: #{e.class}: #{e.message}")
      []
    end

    def self.matched_promo_tag_names_by_topic(topic_ids, promo_tag_names)
      ids = Array(topic_ids).map(&:to_i).reject(&:zero?).uniq
      names = Array(promo_tag_names).map { |t| t.to_s.strip.downcase }.reject(&:empty?).uniq
      return {} if ids.blank? || names.blank?

      tags = Tag.where("LOWER(name) IN (?)", names).pluck(:id, :name)
      return {} if tags.blank?

      tag_id_to_name = {}
      tag_ids = []
      tags.each do |tid, tname|
        tag_ids << tid
        tag_id_to_name[tid.to_i] = tname.to_s
      end

      rows = TopicTag.where(topic_id: ids, tag_id: tag_ids).pluck(:topic_id, :tag_id)
      out = Hash.new { |h, k| h[k] = [] }

      rows.each do |topic_id, tag_id|
        name = tag_id_to_name[tag_id.to_i]
        next if name.blank?
        out[topic_id.to_i] << name
      end

      out.each { |k, arr| out[k] = arr.uniq }
      out
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] matched_promo_tag_names_by_topic failed: #{e.class}: #{e.message}")
      {}
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

    # SUPERPROMO watched categories (independent knobs)
    def self.watched_category_ids_for_user_superpromo(user)
      return [] unless ::PromoDigestConfig::SUPERPROMO_USE_WATCHED_CATEGORIES
      return [] if user.nil?

      levels = []
      if defined?(CategoryUser) && CategoryUser.respond_to?(:notification_levels)
        nl = CategoryUser.notification_levels
        levels << (nl[:watching] || 3)
        if ::PromoDigestConfig::SUPERPROMO_INCLUDE_WATCHING_FIRST_POST
          levels << (nl[:watching_first_post] || 4)
        end
      else
        levels = ::PromoDigestConfig::SUPERPROMO_INCLUDE_WATCHING_FIRST_POST ? [3, 4] : [3]
      end

      CategoryUser.where(user_id: user.id, notification_level: levels).pluck(:category_id)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] watched_category_ids_for_user_superpromo failed: #{e.class}: #{e.message}")
      []
    end

    # ----------------------------
    # Ensure first digest topic is from a watched category (swap-based)
    # ----------------------------
    def self.ensure_first_topic_from_watched_category(
      user,
      ids,
      promo_tag_ids: nil,
      prefer_promo_only_if_first_is_promo: false
    )
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

      rows =
        Topic
          .visible
          .secured(guardian)
          .where(id: window_ids)
          .pluck(:id, :category_id, :created_at)

      return ids if rows.blank?

      watched_rows = rows.select { |_tid, cid, _created| cid && watched_ids.include?(cid) }
      return ids if watched_rows.blank?

      preferred_rows = watched_rows
      if prefer_promo_only_if_first_is_promo && promo_tag_ids.present?
        promo_ids =
          TopicTag
            .where(topic_id: watched_rows.map { |tid, _cid, _c| tid }, tag_id: Array(promo_tag_ids).map(&:to_i))
            .distinct
            .pluck(:topic_id)
            .map(&:to_i)
            .to_set

        promo_rows = watched_rows.select { |tid, _cid, _created| promo_ids.include?(tid.to_i) }
        preferred_rows = promo_rows if promo_rows.present?
      end

      require_created_after = (::PromoDigestConfig::FORCE_FIRST_TOPIC_REQUIRE_CREATED_AFTER_LAST_DIGEST == true)
      soft_fallback = (::PromoDigestConfig::FORCE_FIRST_TOPIC_SOFT_FALLBACK == true)

      last_ts = nil
      last_ts = last_digest_sent_at_for_user(user) if require_created_after

      top_n = ::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOM_TOP_N.to_i
      top_n = 5 if top_n <= 0

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
        newer = preferred_rows.select { |_tid, _cid, created| created.present? && created > last_ts }
        if newer.present?
          chosen = pick_random_from_top.call(newer)
        elsif soft_fallback
          chosen = pick_random_from_top.call(preferred_rows)
        else
          return ids
        end
      else
        chosen = pick_random_from_top.call(preferred_rows)
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
    def self.eligible_promo_set_within_digest_list(user, tag_ids:, digest_ids:, created_after: nil)
      return [Set.new, 0, 0, [], false] if user.nil?
      return [Set.new, 0, 0, [], false] if tag_ids.blank?
      return [Set.new, 0, 0, [], false] if digest_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user(user)
      watched_filter_applied = watched_ids.present?

      scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_ids, topic_id: digest_ids })
          .distinct

      scope = scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestConfig::FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST == true && created_after.present?
        scope = scope.where("topics.created_at > ?", created_after)
      end

      candidate_ids = scope.pluck("topic_tags.topic_id").map(&:to_i).uniq
      candidate_pool_count = candidate_ids.length
      return [Set.new, candidate_pool_count, 0, watched_ids, watched_filter_applied] if candidate_ids.blank?

      visible_ids =
        Topic
          .visible
          .secured(guardian)
          .where(id: candidate_ids)
          .pluck(:id)
          .map(&:to_i)

      visible_pool_count = visible_ids.length
      return [Set.new, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied] if visible_ids.blank?

      [visible_ids.to_set, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] eligible_promo_set_within_digest_list failed: #{e.class}: #{e.message}")
      [Set.new, 0, 0, [], false]
    end

    # ============================================================
    # Prefer-digest-list: eligible SUPERPROMO set inside digest list
    # ============================================================
    def self.eligible_superpromo_set_within_digest_list(user, tag_ids:, digest_ids:, created_after: nil)
      return [Set.new, 0, 0, [], false] if user.nil?
      return [Set.new, 0, 0, [], false] if tag_ids.blank?
      return [Set.new, 0, 0, [], false] if digest_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user_superpromo(user)
      watched_filter_applied = watched_ids.present?

      scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_ids, topic_id: digest_ids })
          .distinct

      scope = scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestConfig::SUPERPROMO_FILTER_TOPICS_CREATED_AFTER_LAST_DIGEST == true && created_after.present?
        scope = scope.where("topics.created_at > ?", created_after)
      end

      candidate_ids = scope.pluck("topic_tags.topic_id").map(&:to_i).uniq
      candidate_pool_count = candidate_ids.length
      return [Set.new, candidate_pool_count, 0, watched_ids, watched_filter_applied] if candidate_ids.blank?

      visible_ids =
        Topic
          .visible
          .secured(guardian)
          .where(id: candidate_ids)
          .pluck(:id)
          .map(&:to_i)

      visible_pool_count = visible_ids.length
      return [Set.new, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied] if visible_ids.blank?

      [visible_ids.to_set, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] eligible_superpromo_set_within_digest_list failed: #{e.class}: #{e.message}")
      [Set.new, 0, 0, [], false]
    end

    # ============================================================
    # Prefer-digest-list: swap eligible promos into target indices
    # ============================================================
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
    def self.pick_random_promo_topic_ids(user, tag_ids:, exclude_ids:, limit:, created_after: nil)
      return [[], 0, 0, [], false] if limit.to_i <= 0
      return [[], 0, 0, [], false] if tag_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user(user)
      watched_filter_applied = watched_ids.present?

      topic_tag_scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_ids })
          .where.not(topic_tags: { topic_id: exclude_ids })
          .distinct

      topic_tag_scope = topic_tag_scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestConfig::FILTER_PROMO_TOPICS_CREATED_AFTER_LAST_DIGEST == true && created_after.present?
        topic_tag_scope = topic_tag_scope.where("topics.created_at > ?", created_after)
      end

      scan_cap = ::PromoDigestConfig::PROMO_CANDIDATE_SCAN_CAP.to_i
      scan_cap = 500 if scan_cap <= 0

      candidate_ids =
        topic_tag_scope
          .limit(scan_cap)
          .pluck("topic_tags.topic_id")
          .map(&:to_i)
          .uniq

      candidate_pool_count = candidate_ids.length
      return [[], candidate_pool_count, 0, watched_ids, watched_filter_applied] if candidate_ids.blank?

      candidate_ids = candidate_ids.shuffle

      visible_ids =
        Topic
          .visible
          .secured(guardian)
          .where(id: candidate_ids)
          .where.not(id: exclude_ids)
          .pluck(:id)
          .map(&:to_i)

      visible_pool_count = visible_ids.length
      return [[], candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied] if visible_ids.blank?

      injected_ids = visible_ids.sample([limit.to_i, visible_ids.length].min)
      [injected_ids, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] pick_random_promo_topic_ids failed: #{e.class}: #{e.message}")
      [[], 0, 0, [], false]
    end

    # ============================================================
    # Global picker (forum-wide) SUPERPROMO
    # ============================================================
    def self.pick_random_superpromo_topic_ids(user, tag_ids:, exclude_ids:, limit:, created_after: nil)
      return [[], 0, 0, [], false] if limit.to_i <= 0
      return [[], 0, 0, [], false] if tag_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user_superpromo(user)
      watched_filter_applied = watched_ids.present?

      topic_tag_scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_ids })
          .where.not(topic_tags: { topic_id: exclude_ids })
          .distinct

      topic_tag_scope = topic_tag_scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestConfig::SUPERPROMO_FILTER_TOPICS_CREATED_AFTER_LAST_DIGEST == true && created_after.present?
        topic_tag_scope = topic_tag_scope.where("topics.created_at > ?", created_after)
      end

      scan_cap = ::PromoDigestConfig::SUPERPROMO_CANDIDATE_SCAN_CAP.to_i
      scan_cap = 500 if scan_cap <= 0

      candidate_ids =
        topic_tag_scope
          .limit(scan_cap)
          .pluck("topic_tags.topic_id")
          .map(&:to_i)
          .uniq

      candidate_pool_count = candidate_ids.length
      return [[], candidate_pool_count, 0, watched_ids, watched_filter_applied] if candidate_ids.blank?

      candidate_ids = candidate_ids.shuffle

      visible_ids =
        Topic
          .visible
          .secured(guardian)
          .where(id: candidate_ids)
          .where.not(id: exclude_ids)
          .pluck(:id)
          .map(&:to_i)

      visible_pool_count = visible_ids.length
      return [[], candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied] if visible_ids.blank?

      picked = visible_ids.sample([limit.to_i, visible_ids.length].min)
      [picked, candidate_pool_count, visible_pool_count, watched_ids, watched_filter_applied]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] pick_random_superpromo_topic_ids failed: #{e.class}: #{e.message}")
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
      promo_tag_ids:,
      promo_tag_names:,
      first_injected_tag_name:,

      original_ids:,
      tagged_ids_in_original:,
      injected_ids:,
      final_ids:,

      original_topics_matched_tags:,
      injected_topics_matched_tags:,

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
      user_watched_category_ids:,

      no_watched_shuffle_enabled:,
      no_watched_shuffle_applied:,
      no_watched_shuffle_top_n:,
      no_watched_shuffle_coinflip_percent:,

      watched_percent_enforcer_applied:,
      watched_percent_debug:,

      # -------- SUPERPROMO --------
      superpromo_tag:,
      superpromo_tag_ids:,
      superpromo_injected_ids:,
      superpromo_attempted_replace:,
      superpromo_replace_indices:,
      superpromo_is_skipped_hastag:,
      superpromo_is_skipped_coinflip:,
      superpromo_candidate_pool_count:,
      superpromo_visible_pool_count:,
      superpromo_watched_category_ids:,
      superpromo_watched_filter_applied:,
      superpromo_pick_mode:,
      superpromo_digest_list_candidates_count:,
      superpromo_digest_list_visible_count:,
      superpromo_digest_list_picked:,
      superpromo_fallback_picked:,
      superpromo_used_fallback_outside_digest:,
      superpromo_created_after_enabled:,
      superpromo_created_after_applied:,

      debug_digest_build_uuid:,
      debug_for_digest_call_index:,
      debug_for_digest_since:,
      debug_for_digest_opts:,
      debug_for_digest_callsite:,
      debug_dedupe_key:
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
        first_injected_tag_name: first_injected_tag_name,

        is_skipped_haspromo: is_skipped_haspromo,
        is_skipped_coinflip: is_skipped_coinflip,
        is_skipped_min_digests: is_skipped_min_digests,
        min_digests_required: min_digests_required,
        user_digest_count: user_digest_count,

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
          digest_build_uuid: debug_digest_build_uuid,
          for_digest_call_index: debug_for_digest_call_index,
          for_digest_since: debug_for_digest_since,
          for_digest_opts: debug_for_digest_opts,
          for_digest_callsite: debug_for_digest_callsite,
          debug_dedupe_key: debug_dedupe_key,

          promo_tag_found: promo_tag_found,
          promo_tag_id: promo_tag_id,
          promo_tag_ids: promo_tag_ids,
          promo_tag_names: promo_tag_names,
          promo_tag_total_topics: promo_tag_total_topics,

          original_topics_matched_tags: original_topics_matched_tags,
          injected_topics_matched_tags: injected_topics_matched_tags,

          attempted_replace: attempted_replace,
          candidate_pool_count: candidate_pool_count,
          visible_pool_count: visible_pool_count,

          user_watched_category_ids: user_watched_category_ids,

          watched_category_ids: watched_category_ids,
          watched_categories_mode: ::PromoDigestConfig::USE_WATCHED_CATEGORIES,
          watched_filter_applied: watched_filter_applied,

          watched_percent_enforcer_enabled: ::PromoDigestConfig::ENFORCE_MIN_WATCHED_CATEGORY_PERCENT,
          watched_percent_enforcer_applied: watched_percent_enforcer_applied,
          watched_percent_enforcer_debug: watched_percent_debug,

          forced_first_topic_from_watched_category_enabled: ::PromoDigestConfig::FORCE_FIRST_TOPIC_FROM_WATCHED_CATEGORY,
          forced_first_topic_coinflip_percent: ::PromoDigestConfig::FORCE_FIRST_TOPIC_WATCHED_COINFLIP_PERCENT,
          force_first_topic_randomize_even_if_already_watched: ::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOMIZE_EVEN_IF_ALREADY_WATCHED,
          force_first_topic_random_top_n: ::PromoDigestConfig::FORCE_FIRST_TOPIC_RANDOM_TOP_N,
          forced_first_topic_require_created_after_last_digest: ::PromoDigestConfig::FORCE_FIRST_TOPIC_REQUIRE_CREATED_AFTER_LAST_DIGEST,
          forced_first_topic_soft_fallback: ::PromoDigestConfig::FORCE_FIRST_TOPIC_SOFT_FALLBACK,
          forced_first_topic_applied: forced_first_applied,

          shuffle_if_no_watched_categories_enabled: no_watched_shuffle_enabled,
          shuffle_if_no_watched_categories_applied: no_watched_shuffle_applied,
          shuffle_if_no_watched_top_n: no_watched_shuffle_top_n,
          shuffle_if_no_watched_coinflip_percent: no_watched_shuffle_coinflip_percent,

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
          replaced_indices: replaced_indices,

          # -------- SUPERPROMO --------
          superpromo: {
            enabled: ::PromoDigestConfig::SUPERPROMO_ENABLED,
            tag: superpromo_tag,
            tag_ids: superpromo_tag_ids,
            injected_topic_ids: superpromo_injected_ids,
            attempted_replace: superpromo_attempted_replace,
            replaced_indices: superpromo_replace_indices,
            is_skipped_hastag: superpromo_is_skipped_hastag,
            is_skipped_coinflip: superpromo_is_skipped_coinflip,
            candidate_pool_count: superpromo_candidate_pool_count,
            visible_pool_count: superpromo_visible_pool_count,
            watched_category_ids: superpromo_watched_category_ids,
            watched_categories_mode: ::PromoDigestConfig::SUPERPROMO_USE_WATCHED_CATEGORIES,
            watched_filter_applied: superpromo_watched_filter_applied,
            pick_mode: superpromo_pick_mode,
            digest_list_candidates_count: superpromo_digest_list_candidates_count,
            digest_list_visible_count: superpromo_digest_list_visible_count,
            digest_list_picked: superpromo_digest_list_picked,
            used_fallback_outside_digest: superpromo_used_fallback_outside_digest,
            fallback_picked: superpromo_fallback_picked,
            created_after_last_digest_filter_enabled: superpromo_created_after_enabled,
            created_after_last_digest_filter_applied: superpromo_created_after_applied
          }
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

  # ============================================================
  # Wrapper: sets build UUID + resets call counter per digest build
  # ============================================================
  module ::PromoDigestDigestWrapper
    def digest(user, opts = {})
      Thread.current[:promo_digest_in_digest] = true
      Thread.current[:promo_digest_build_uuid] = SecureRandom.hex(8)
      Thread.current[:promo_digest_for_digest_call_index] = 0

      Thread.current[:promo_digest_since] = nil
      Thread.current[:promo_digest_opts_sanitized] = nil
      Thread.current[:promo_digest_callsite] = nil

      super
    ensure
      Thread.current[:promo_digest_in_digest] = false
    end
  end
  ::UserNotifications.prepend ::PromoDigestDigestWrapper

  # ============================================================
  # Hook: captures since/opts/callsite for each Topic.for_digest call,
  # then ONLY injects/logs for the REAL digest call:
  #   opts is Hash AND opts[:top_order] == true AND opts[:limit] present
  # (skips Post.for_mailing_list calls, etc.)
  # ============================================================
  module ::PromoDigestForDigestOverride
    def for_digest(user, since, opts = nil)
      if Thread.current[:promo_digest_in_digest] == true
        Thread.current[:promo_digest_for_digest_call_index] =
          (Thread.current[:promo_digest_for_digest_call_index].to_i + 1)

        Thread.current[:promo_digest_since] = since
        Thread.current[:promo_digest_opts_sanitized] = ::PromoDigestInjector.sanitize_opts_for_debug(opts)

        depth = ::PromoDigestConfig::DEBUG_CALLSITE_DEPTH.to_i
        depth = 10 if depth <= 0
        Thread.current[:promo_digest_callsite] = caller_locations(0, depth).map(&:to_s)
      end

      rel = super(user, since, opts)

      # Guard: only run injector for the real digest for_digest call
      return rel unless Thread.current[:promo_digest_in_digest] == true
      return rel unless opts.is_a?(Hash)

      limit_val = opts[:limit] || opts["limit"]
      top_order = opts[:top_order]
      top_order = opts["top_order"] if top_order.nil?

      return rel if limit_val.to_i <= 0
      return rel unless top_order == true

      ::PromoDigestInjector.maybe_adjust_digest_topics(user, rel, opts)
    end
  end
  ::Topic.singleton_class.prepend ::PromoDigestForDigestOverride
end
