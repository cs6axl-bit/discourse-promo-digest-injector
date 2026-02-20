# frozen_string_literal: true
# name: discourse-promo-digest-injector
# about: Ensures digest includes tag-marked topics near the top (with optional random injection) and posts a run summary to an external endpoint (async, non-blocking). Optionally restricts promo picks to categories the user is "watching". Also (A) requires a minimum number of digests before injecting and (B) stores last 50 FINAL digest topic IDs per user (newest digest first, duplicates allowed). Stores last 10 FINAL position-0 topic IDs per user (newest first, duplicates allowed). If user has NO watched categories, can optionally shuffle the first N digest topics. If first topic is promo, forced-first swapping prefers promo-only candidates (fallback to any watched). Enforce min % of watched-category topics in digest list. DEBUG: adds digest_build_uuid + for_digest_call_index + since/opts/callsite into debug payload. FIX: only inject/log for the REAL digest for_digest call (opts[:top_order]==true + opts[:limit] present), skipping Post.for_mailing_list calls etc.
# version: 1.7.1
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
  # SETTINGS HELPERS
  # ============================================================
  module ::PromoDigestSettings
    def self.enabled?
      SiteSetting.promo_digest_injector_enabled == true
    end

    # Independent master switch for REGULAR promo injection only
    # (superpromo/hardsale remain independent)
    def self.regular_injection_enabled?
      SiteSetting.promo_digest_injector_regular_enabled == true
    end

    # ============================================================
    # PUSH SPECIFIC (HARD OVERRIDE) + DYNAMIC PICKER
    #
    # If enabled, push logic MAY override the digest to contain ONLY ONE topic,
    # depending on:
    #  - (optional) "recent push digest" cooldown gate
    #  - coinflip apply percent
    #  - source:
    #      (1) explicit topic id via settings
    #      (2) dynamic picker (A1/A2/B stages)
    #
    # If push is applied: ALL other injection/swaps are skipped.
    # ============================================================
    def self.push_specific_enabled?
      return false unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_enabled)
      SiteSetting.promo_digest_injector_push_specific_enabled == true
    rescue
      false
    end

    def self.push_specific_topic_id
      return 0 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_topic_id)
      SiteSetting.promo_digest_injector_push_specific_topic_id.to_i
    rescue
      0
    end

    # Coinflip percent to apply push flow (0..100). If 0 => never, 100 => always (subject to other gates).
    def self.push_specific_apply_percent
      return 100 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_apply_percent)
      v = SiteSetting.promo_digest_injector_push_specific_apply_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    rescue
      100
    end

    # Optional pre-gate: if user received ANY push-type digest within last X days, skip push entirely (before coinflip).
    def self.push_specific_skip_if_recent_push_enabled?
      return false unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_skip_if_recent_push_enabled)
      SiteSetting.promo_digest_injector_push_specific_skip_if_recent_push_enabled == true
    rescue
      false
    end

    def self.push_specific_skip_if_recent_push_days
      return 0 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_skip_if_recent_push_days)
      v = SiteSetting.promo_digest_injector_push_specific_skip_if_recent_push_days.to_i
      v < 0 ? 0 : v
    rescue
      0
    end

    # Dynamic picker enable
    def self.push_specific_dynamic_enabled?
      return false unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_dynamic_enabled)
      SiteSetting.promo_digest_injector_push_specific_dynamic_enabled == true
    rescue
      false
    end

    # Dynamic picker tags (pipe-separated), eg: "verified|featured"
    def self.push_specific_dynamic_tags
      return ["verified"] unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_dynamic_tags)
      raw = SiteSetting.promo_digest_injector_push_specific_dynamic_tags.to_s
      tags = raw.split("|").map { |t| t.to_s.strip.downcase }.reject(&:empty?).uniq
      tags = ["verified"] if tags.blank?
      tags
    rescue
      ["verified"]
    end

    # Dynamic: require created_after_last_digest (optional)
    def self.push_specific_dynamic_require_created_after_last_digest?
      return false unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_dynamic_require_created_after_last_digest)
      SiteSetting.promo_digest_injector_push_specific_dynamic_require_created_after_last_digest == true
    rescue
      false
    end

    # Dynamic Stage A2: lookahead extra beyond digest limit
    def self.push_specific_dynamic_lookahead_extra
      return 50 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_dynamic_lookahead_extra)
      v = SiteSetting.promo_digest_injector_push_specific_dynamic_lookahead_extra.to_i
      v < 0 ? 0 : v
    rescue
      50
    end

    # Dynamic Stage B: forum scan cap
    def self.push_specific_dynamic_forum_scan_cap
      return 500 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_dynamic_forum_scan_cap)
      v = SiteSetting.promo_digest_injector_push_specific_dynamic_forum_scan_cap.to_i
      v <= 0 ? 500 : v
    rescue
      500
    end

    # Exclude topics pushed recently (per-user history) when using dynamic picker
    def self.push_specific_exclude_recent_pushed?
      return true unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_exclude_recent_pushed)
      SiteSetting.promo_digest_injector_push_specific_exclude_recent_pushed == true
    rescue
      true
    end

    def self.push_specific_exclude_recent_pushed_days
      return 30 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_exclude_recent_pushed_days)
      v = SiteSetting.promo_digest_injector_push_specific_exclude_recent_pushed_days.to_i
      v < 0 ? 0 : v
    rescue
      30
    end

    # Push history custom field (JSON array of objects)
    def self.push_specific_pushed_history_field
      return "promo_digest_pushed_topics_last50" unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_pushed_history_field)
      SiteSetting.promo_digest_injector_push_specific_pushed_history_field.to_s.strip
    rescue
      "promo_digest_pushed_topics_last50"
    end

    def self.push_specific_pushed_history_max
      return 50 unless SiteSetting.respond_to?(:promo_digest_injector_push_specific_pushed_history_max)
      v = SiteSetting.promo_digest_injector_push_specific_pushed_history_max.to_i
      v <= 0 ? 50 : v
    rescue
      50
    end

    # ============================================================
    # SUPERPUSH (NEW)
    # If user watches ANY superpush categories, restrict push picks
    # to the INTERSECTION (watched ∩ superpush_categories).
    # If none watched, behave normally.
    # ============================================================
    def self.superpush_enabled?
      return false unless SiteSetting.respond_to?(:promo_digest_injector_superpush_enabled)
      SiteSetting.promo_digest_injector_superpush_enabled == true
    rescue
      false
    end

    # Coinflip percent to apply superpush restriction when user qualifies (0..100)
    def self.superpush_apply_percent
      return 100 unless SiteSetting.respond_to?(:promo_digest_injector_superpush_apply_percent)
      v = SiteSetting.promo_digest_injector_superpush_apply_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    rescue
      100
    end

    # Pipe-separated category IDs, e.g. "9|14|22"
    def self.superpush_category_ids
      return [] unless SiteSetting.respond_to?(:promo_digest_injector_superpush_category_ids)
      raw = SiteSetting.promo_digest_injector_superpush_category_ids.to_s
      raw
        .split("|")
        .map { |x| x.to_s.strip }
        .reject(&:empty?)
        .map { |x| x.to_i }
        .reject(&:zero?)
        .uniq
    rescue
      []
    end

    # ---------------- Existing settings ----------------
    def self.min_digests_before_inject
      v = SiteSetting.promo_digest_injector_min_digests_before_inject.to_i
      v < 0 ? 0 : v
    end

    def self.digest_count_custom_field
      SiteSetting.promo_digest_injector_digest_count_custom_field.to_s.strip
    end

    def self.promo_tags
      raw = SiteSetting.promo_digest_injector_promo_tags.to_s
      raw.split("|").map { |t| t.to_s.strip.downcase }.reject(&:empty?).uniq
    end

    def self.use_watched_categories?
      SiteSetting.promo_digest_injector_use_watched_categories == true
    end

    def self.include_watching_first_post?
      SiteSetting.promo_digest_injector_include_watching_first_post == true
    end

    def self.min_position
      v = SiteSetting.promo_digest_injector_min_position.to_i
      v <= 0 ? 3 : v
    end

    def self.coinflip_skip_percent
      v = SiteSetting.promo_digest_injector_coinflip_skip_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    end

    def self.replace_within_top_n
      v = SiteSetting.promo_digest_injector_replace_within_top_n.to_i
      v <= 0 ? 3 : v
    end

    def self.replace_count
      v = SiteSetting.promo_digest_injector_replace_count.to_i
      v <= 0 ? 1 : v
    end

    def self.default_digest_limit
      v = SiteSetting.promo_digest_injector_default_digest_limit.to_i
      v <= 0 ? 50 : v
    end

    def self.endpoint_url
      SiteSetting.promo_digest_injector_endpoint_url.to_s.strip
    end

    def self.secret_header_value
      SiteSetting.promo_digest_injector_secret_header_value.to_s
    end

    def self.log_post_results?
      SiteSetting.promo_digest_injector_log_post_results == true
    end

    def self.http_open_timeout
      v = SiteSetting.promo_digest_injector_http_open_timeout.to_i
      v <= 0 ? 3 : v
    end

    def self.http_read_timeout
      v = SiteSetting.promo_digest_injector_http_read_timeout.to_i
      v <= 0 ? 5 : v
    end

    def self.send_ids_only?
      SiteSetting.promo_digest_injector_send_ids_only == true
    end

    def self.last_digest_topics_field
      SiteSetting.promo_digest_injector_last_digest_topics_field.to_s.strip
    end

    def self.last_digest_topics_max
      v = SiteSetting.promo_digest_injector_last_digest_topics_max.to_i
      v <= 0 ? 50 : v
    end

    def self.last_digest_first_topics_field
      SiteSetting.promo_digest_injector_last_digest_first_topics_field.to_s.strip
    end

    def self.last_digest_first_topics_max
      v = SiteSetting.promo_digest_injector_last_digest_first_topics_max.to_i
      v <= 0 ? 10 : v
    end

    def self.force_first_topic_from_watched_category?
      SiteSetting.promo_digest_injector_force_first_topic_from_watched_category == true
    end

    def self.force_first_topic_watched_coinflip_percent
      v = SiteSetting.promo_digest_injector_force_first_topic_watched_coinflip_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    end

    def self.force_first_topic_randomize_even_if_already_watched?
      SiteSetting.promo_digest_injector_force_first_topic_randomize_even_if_already_watched == true
    end

    def self.force_first_topic_random_top_n
      v = SiteSetting.promo_digest_injector_force_first_topic_random_top_n.to_i
      v <= 0 ? 5 : v
    end

    def self.force_first_topic_require_created_after_last_digest?
      SiteSetting.promo_digest_injector_force_first_topic_require_created_after_last_digest == true
    end

    def self.force_first_topic_soft_fallback?
      SiteSetting.promo_digest_injector_force_first_topic_soft_fallback == true
    end

    def self.force_first_topic_lookahead
      v = SiteSetting.promo_digest_injector_force_first_topic_lookahead.to_i
      v <= 0 ? 50 : v
    end

    def self.filter_promo_topics_created_after_last_digest?
      SiteSetting.promo_digest_injector_filter_promo_topics_created_after_last_digest == true
    end

    def self.shuffle_topics_if_no_watched_categories?
      SiteSetting.promo_digest_injector_shuffle_topics_if_no_watched_categories == true
    end

    def self.shuffle_topics_if_no_watched_top_n
      v = SiteSetting.promo_digest_injector_shuffle_topics_if_no_watched_top_n.to_i
      v <= 0 ? 4 : v
    end

    def self.shuffle_topics_if_no_watched_coinflip_percent
      v = SiteSetting.promo_digest_injector_shuffle_topics_if_no_watched_coinflip_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    end

    def self.promo_pick_mode
      m = SiteSetting.promo_digest_injector_promo_pick_mode.to_s.strip
      m = "prefer_digest_list" if m.empty?
      m
    end

    def self.promo_candidate_scan_cap
      v = SiteSetting.promo_digest_injector_promo_candidate_scan_cap.to_i
      v <= 0 ? 500 : v
    end

    def self.enforce_min_watched_category_percent?
      SiteSetting.promo_digest_injector_enforce_min_watched_category_percent == true
    end

    def self.min_watched_category_percent
      v = SiteSetting.promo_digest_injector_min_watched_category_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    end

    def self.watched_enforce_lookahead_extra
      v = SiteSetting.promo_digest_injector_watched_enforce_lookahead_extra.to_i
      v < 0 ? 0 : v
    end

    def self.watched_enforce_forum_scan_cap
      v = SiteSetting.promo_digest_injector_watched_enforce_forum_scan_cap.to_i
      v <= 0 ? 500 : v
    end

    # -------- SUPERPROMO --------
    def self.superpromo_enabled?
      SiteSetting.promo_digest_injector_superpromo_enabled == true
    end

    def self.superpromo_tags
      raw = SiteSetting.promo_digest_injector_superpromo_tags.to_s
      raw.split("|").map { |t| t.to_s.strip.downcase }.reject(&:empty?).uniq
    end

    def self.superpromo_use_watched_categories?
      SiteSetting.promo_digest_injector_superpromo_use_watched_categories == true
    end

    def self.superpromo_include_watching_first_post?
      SiteSetting.promo_digest_injector_superpromo_include_watching_first_post == true
    end

    def self.superpromo_min_position
      v = SiteSetting.promo_digest_injector_superpromo_min_position.to_i
      v <= 0 ? 3 : v
    end

    def self.superpromo_coinflip_skip_percent
      v = SiteSetting.promo_digest_injector_superpromo_coinflip_skip_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    end

    def self.superpromo_replace_within_top_n
      v = SiteSetting.promo_digest_injector_superpromo_replace_within_top_n.to_i
      v <= 0 ? 3 : v
      v
    end

    def self.superpromo_replace_count
      v = SiteSetting.promo_digest_injector_superpromo_replace_count.to_i
      v <= 0 ? 1 : v
      v
    end

    def self.superpromo_filter_topics_created_after_last_digest?
      SiteSetting.promo_digest_injector_superpromo_filter_topics_created_after_last_digest == true
    end

    def self.superpromo_pick_mode
      m = SiteSetting.promo_digest_injector_superpromo_pick_mode.to_s.strip
      m = "prefer_digest_list" if m.empty?
      m
    end

    def self.superpromo_candidate_scan_cap
      v = SiteSetting.promo_digest_injector_superpromo_candidate_scan_cap.to_i
      v <= 0 ? 500 : v
    end

    # -------- HARDSALE (NEW) --------
    def self.hardsale_enabled?
      SiteSetting.promo_digest_injector_hardsale_enabled == true
    end

    def self.hardsale_tags
      raw = SiteSetting.promo_digest_injector_hardsale_tags.to_s
      raw.split("|").map { |t| t.to_s.strip.downcase }.reject(&:empty?).uniq
    end

    def self.hardsale_use_watched_categories?
      SiteSetting.promo_digest_injector_hardsale_use_watched_categories == true
    end

    def self.hardsale_include_watching_first_post?
      SiteSetting.promo_digest_injector_hardsale_include_watching_first_post == true
    end

    def self.hardsale_min_position
      v = SiteSetting.promo_digest_injector_hardsale_min_position.to_i
      v <= 0 ? 3 : v
    end

    def self.hardsale_coinflip_skip_percent
      v = SiteSetting.promo_digest_injector_hardsale_coinflip_skip_percent.to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    end

    def self.hardsale_replace_within_top_n
      v = SiteSetting.promo_digest_injector_hardsale_replace_within_top_n.to_i
      v <= 0 ? 3 : v
      v
    end

    def self.hardsale_replace_count
      v = SiteSetting.promo_digest_injector_hardsale_replace_count.to_i
      v <= 0 ? 1 : v
      v
    end

    def self.hardsale_filter_topics_created_after_last_digest?
      SiteSetting.promo_digest_injector_hardsale_filter_topics_created_after_last_digest == true
    end

    def self.hardsale_pick_mode
      m = SiteSetting.promo_digest_injector_hardsale_pick_mode.to_s.strip
      m = "prefer_digest_list" if m.empty?
      m
    end

    def self.hardsale_candidate_scan_cap
      v = SiteSetting.promo_digest_injector_hardsale_candidate_scan_cap.to_i
      v <= 0 ? 500 : v
    end

    # -------- DEBUG --------
    def self.debug_callsite_depth
      v = SiteSetting.promo_digest_injector_debug_callsite_depth.to_i
      v <= 0 ? 10 : v
    end

    def self.debug_include_opts?
      SiteSetting.promo_digest_injector_debug_include_opts == true
    end
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

      cf_key = ::PromoDigestSettings.digest_count_custom_field
      if cf_key != ""
        cf_val = user.custom_fields[cf_key]
        return cf_val.to_i if cf_val.present?
      end

      min_needed = ::PromoDigestSettings.min_digests_before_inject
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

    # ============================================================
    # SUPERPUSH CONTEXT (NEW)
    # Determines if superpush restriction is active for this user,
    # and returns the watched categories to use for PUSH selection.
    # ============================================================
    def self.superpush_context_for_user(user, watched_ids_all)
      watched_ids_all = Array(watched_ids_all).map(&:to_i).reject(&:zero?).uniq
      sp_enabled = ::PromoDigestSettings.superpush_enabled?
      sp_apply_pct = ::PromoDigestSettings.superpush_apply_percent
      sp_cat_ids = ::PromoDigestSettings.superpush_category_ids

      ctx = {
        enabled: sp_enabled,
        apply_percent: sp_apply_pct,
        configured_category_ids: sp_cat_ids,
        user_watched_all: watched_ids_all,
        user_watched_superpush: [],
        qualifies: false,
        coinflip_passed: false,
        active: false,
        used_category_ids: watched_ids_all,
        fallback_to_regular_due_to_no_candidates: false
      }

      return ctx if user.nil?
      return ctx unless sp_enabled
      return ctx if sp_cat_ids.blank?
      return ctx if watched_ids_all.blank?

      watched_super = watched_ids_all & sp_cat_ids
      ctx[:user_watched_superpush] = watched_super
      ctx[:qualifies] = watched_super.present?
      return ctx unless ctx[:qualifies]

      if sp_apply_pct.to_i <= 0
        ctx[:coinflip_passed] = false
        return ctx
      end

      ctx[:coinflip_passed] =
        (sp_apply_pct.to_i >= 100) || (rand(100) < sp_apply_pct.to_i)

      return ctx unless ctx[:coinflip_passed]

      ctx[:active] = true
      ctx[:used_category_ids] = watched_super
      ctx
    rescue
      {
        enabled: false,
        apply_percent: 0,
        configured_category_ids: [],
        user_watched_all: Array(watched_ids_all).map(&:to_i).reject(&:zero?).uniq,
        user_watched_superpush: [],
        qualifies: false,
        coinflip_passed: false,
        active: false,
        used_category_ids: Array(watched_ids_all).map(&:to_i).reject(&:zero?).uniq,
        fallback_to_regular_due_to_no_candidates: false
      }
    end

    # ============================================================
    # PUSH HISTORY (per-user) helpers
    # Stored in user.custom_fields[push_history_field] as JSON array:
    #   [{ "ts":"2026-02-18T12:34:56Z", "topic_id":123, "category_id":9, "title":"first 50 chars" }, ...]
    # Newest first. Duplicates allowed.
    # ============================================================
    def self.push_history_field
      ::PromoDigestSettings.push_specific_pushed_history_field
    end

    def self.push_history_max
      ::PromoDigestSettings.push_specific_pushed_history_max
    end

    def self.read_push_history_entries(user)
      return [] if user.nil?
      field = push_history_field
      return [] if field.blank?

      raw = user.custom_fields[field].to_s
      arr =
        begin
          JSON.parse(raw)
        rescue
          []
        end
      arr = Array(arr)
      arr.select { |x| x.is_a?(Hash) }
    rescue
      []
    end

    def self.push_received_within_days?(user, days)
      return false if user.nil?
      d = days.to_i
      return false if d <= 0

      cutoff = Time.now.utc - (d * 24 * 60 * 60)
      read_push_history_entries(user).any? do |h|
        ts = h["ts"] || h[:ts]
        next false if ts.blank?
        t =
          begin
            Time.parse(ts.to_s).utc
          rescue
            nil
          end
        t.present? && t >= cutoff
      end
    rescue
      false
    end

    def self.pushed_topic_ids_within_days(user, days)
      return Set.new if user.nil?
      d = days.to_i
      return Set.new if d <= 0

      cutoff = Time.now.utc - (d * 24 * 60 * 60)

      out = Set.new
      read_push_history_entries(user).each do |h|
        ts = h["ts"] || h[:ts]
        tid = (h["topic_id"] || h[:topic_id]).to_i
        next if tid <= 0 || ts.blank?

        t =
          begin
            Time.parse(ts.to_s).utc
          rescue
            nil
          end
        next if t.nil? || t < cutoff

        out.add(tid)
      end
      out
    rescue
      Set.new
    end

    def self.persist_pushed_topic_history(user, topic_id)
      return if user.nil?
      tid = topic_id.to_i
      return if tid <= 0

      field = push_history_field
      return if field.blank?

      max_n = push_history_max
      now_iso = Time.now.utc.iso8601

      row = Topic.where(id: tid).pluck(:category_id, :title).first
      category_id = row ? row[0].to_i : 0
      title = row ? row[1].to_s : ""
      title50 = title.to_s[0, 50]

      entry = {
        "ts" => now_iso,
        "topic_id" => tid,
        "category_id" => category_id,
        "title" => title50
      }

      User.transaction do
        u = User.lock.find(user.id)

        prev_raw = u.custom_fields[field].to_s
        prev =
          begin
            JSON.parse(prev_raw)
          rescue
            []
          end
        prev = Array(prev).select { |x| x.is_a?(Hash) }

        combined = ([entry] + prev).first(max_n)

        u.custom_fields[field] = combined.to_json
        u.save_custom_fields(true)
      end
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] persist_pushed_topic_history failed: #{e.class}: #{e.message}")
    end

    # ----------------------------
    # Store last N FINAL digest topics (newest first, duplicates allowed)
    # ----------------------------
    def self.persist_last_digest_topics(user, topic_ids)
      return if user.nil?

      field = ::PromoDigestSettings.last_digest_topics_field
      return if field.strip.empty?

      max_n = ::PromoDigestSettings.last_digest_topics_max

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
    # Store last N FINAL position-0 topic ids (newest first, duplicates allowed)
    # ----------------------------
    def self.persist_last_digest_first_topic(user, first_topic_id)
      return if user.nil?

      field = ::PromoDigestSettings.last_digest_first_topics_field
      return if field.strip.empty?

      max_n = ::PromoDigestSettings.last_digest_first_topics_max

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
      return [ids, false, {}, []] unless ::PromoDigestSettings.enforce_min_watched_category_percent?

      watched_ids = watched_category_ids_for_user(user)
      return [ids, false, {}, watched_ids] if watched_ids.blank?

      pct = ::PromoDigestSettings.min_watched_category_percent
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
      lookahead_extra = ::PromoDigestSettings.watched_enforce_lookahead_extra

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
        scan_cap = ::PromoDigestSettings.watched_enforce_forum_scan_cap

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
      return nil unless ::PromoDigestSettings.debug_include_opts?
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

    # ============================================================
    # PUSH DYNAMIC PICKER (A1/A2/B) — UPDATED for SUPERPUSH
    #
    # If user watches any "superpush categories" and superpush coinflip passes:
    #   - Restrict watched_category_ids to (watched ∩ superpush_categories)
    #   - If no candidates found under that restriction => FALLBACK to regular watched logic
    #
    # If user does NOT watch any superpush categories => unchanged behavior.
    # ============================================================
    def self.pick_dynamic_push_topic_id(user, base_relation, limit:, last_digest_sent_at:)
      return [nil, nil, {}] if user.nil?
      return [nil, nil, {}] if base_relation.blank?

      tags = ::PromoDigestSettings.push_specific_dynamic_tags
      tag_models = tags.map { |t| find_tag_by_name_ci(t) }.compact
      tag_ids = tag_models.map(&:id).compact.uniq
      return [nil, nil, { dynamic_tags: tags, stage: nil, candidates: {} }] if tag_ids.blank?

      guardian = Guardian.new(user)

      watched_all = watched_category_ids_for_user_always(user)
      return [nil, nil, { dynamic_tags: tags, stage: nil, candidates: {}, watched_category_ids: [] }] if watched_all.blank?

      sp_ctx = superpush_context_for_user(user, watched_all)
      watched_ids = sp_ctx[:used_category_ids]

      created_after_required = ::PromoDigestSettings.push_specific_dynamic_require_created_after_last_digest?
      created_after = (created_after_required ? last_digest_sent_at : nil)

      exclude_recent = ::PromoDigestSettings.push_specific_exclude_recent_pushed?
      exclude_days = ::PromoDigestSettings.push_specific_exclude_recent_pushed_days
      exclude_set = (exclude_recent && exclude_days.to_i > 0) ? pushed_topic_ids_within_days(user, exclude_days) : Set.new

      debug = {
        dynamic_tags: tags,
        tag_ids: tag_ids,
        watched_category_ids: watched_ids,
        watched_category_ids_all: watched_all,
        superpush: sp_ctx,
        created_after_required: created_after_required,
        created_after_ts: (created_after.present? ? created_after.utc.iso8601 : nil),
        exclude_recent_pushed_enabled: exclude_recent,
        exclude_recent_pushed_days: exclude_days,
        excluded_recent_topic_ids_count: exclude_set.length,
        stage: nil,
        candidates: { a1: 0, a2: 0, b: 0 }
      }

      picker_run = lambda do |watched_category_ids|
        a1_ids =
          base_relation
            .limit(limit.to_i)
            .pluck(:id)
            .map(&:to_i)
            .reject(&:zero?)

        a1_candidates = eligible_tagged_candidates_in_ids(
          user,
          guardian,
          ids: a1_ids,
          tag_ids: tag_ids,
          watched_category_ids: watched_category_ids,
          created_after: created_after,
          exclude_ids_set: exclude_set
        )

        if a1_candidates.present?
          return [a1_candidates.sample, "dynamic_A1", { stage: "A1", cand_a1: a1_candidates.length }]
        end

        extra = ::PromoDigestSettings.push_specific_dynamic_lookahead_extra
        if extra.to_i > 0
          a2_full =
            base_relation
              .limit(limit.to_i + extra.to_i)
              .pluck(:id)
              .map(&:to_i)
              .reject(&:zero?)

          a2_ids = a2_full.drop(limit.to_i)

          a2_candidates = eligible_tagged_candidates_in_ids(
            user,
            guardian,
            ids: a2_ids,
            tag_ids: tag_ids,
            watched_category_ids: watched_category_ids,
            created_after: created_after,
            exclude_ids_set: exclude_set
          )

          if a2_candidates.present?
            return [a2_candidates.sample, "dynamic_A2", { stage: "A2", cand_a2: a2_candidates.length }]
          end
        end

        scan_cap = ::PromoDigestSettings.push_specific_dynamic_forum_scan_cap

        scope =
          TopicTag
            .joins(:topic)
            .where(topic_tags: { tag_id: tag_ids })
            .where(topics: { category_id: watched_category_ids })
            .distinct

        scope = scope.where("topics.created_at > ?", created_after) if created_after.present?
        scope = scope.where.not(topic_tags: { topic_id: exclude_set.to_a }) if exclude_set.present?

        cand_ids =
          scope
            .limit(scan_cap)
            .pluck("topic_tags.topic_id")
            .map(&:to_i)
            .uniq

        visible_ids =
          Topic
            .visible
            .secured(guardian)
            .where(id: cand_ids)
            .pluck(:id)
            .map(&:to_i)

        if visible_ids.present?
          return [visible_ids.sample, "dynamic_B", { stage: "B", cand_b: visible_ids.length }]
        end

        [nil, nil, { stage: nil, cand_a1: 0, cand_a2: 0, cand_b: 0 }]
      end

      picked_id, src, mini = picker_run.call(watched_ids)

      debug[:stage] = mini[:stage] if mini && mini[:stage]
      if picked_id.to_i > 0
        case mini[:stage]
        when "A1" then debug[:candidates][:a1] = mini[:cand_a1].to_i
        when "A2" then debug[:candidates][:a2] = mini[:cand_a2].to_i
        when "B"  then debug[:candidates][:b]  = mini[:cand_b].to_i
        end
        return [picked_id.to_i, src, debug]
      end

      if sp_ctx[:active] && watched_all.present? && watched_all != watched_ids
        sp_ctx[:fallback_to_regular_due_to_no_candidates] = true
        debug[:superpush] = sp_ctx

        picked2, src2, mini2 = picker_run.call(watched_all)
        if picked2.to_i > 0
          debug[:watched_category_ids] = watched_all
          debug[:stage] = mini2[:stage] if mini2 && mini2[:stage]
          return [picked2.to_i, "#{src2}_superpush_fallback", debug]
        end
      end

      [nil, nil, debug]
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] pick_dynamic_push_topic_id failed: #{e.class}: #{e.message}")
      [nil, nil, {}]
    end

    def self.eligible_tagged_candidates_in_ids(user, guardian, ids:, tag_ids:, watched_category_ids:, created_after:, exclude_ids_set:)
      return [] if user.nil?
      return [] if guardian.nil?
      ids2 = Array(ids).map(&:to_i).reject(&:zero?).uniq
      return [] if ids2.blank?
      t_ids = Array(tag_ids).map(&:to_i).reject(&:zero?).uniq
      return [] if t_ids.blank?
      cids = Array(watched_category_ids).map(&:to_i).reject(&:zero?).uniq
      return [] if cids.blank?

      scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { topic_id: ids2, tag_id: t_ids })
          .where(topics: { category_id: cids })
          .distinct

      scope = scope.where("topics.created_at > ?", created_after) if created_after.present?

      cand_ids = scope.pluck("topic_tags.topic_id").map(&:to_i).uniq
      return [] if cand_ids.blank?

      if exclude_ids_set.present?
        cand_ids = cand_ids.reject { |tid| exclude_ids_set.include?(tid) }
      end
      return [] if cand_ids.blank?

      Topic
        .visible
        .secured(guardian)
        .where(id: cand_ids)
        .pluck(:id)
        .map(&:to_i)
    rescue
      []
    end

    # ----------------------------
    # Main hook
    # ----------------------------
    def self.maybe_adjust_digest_topics(user, original_relation, opts)
      return original_relation unless ::PromoDigestSettings.enabled?
      return original_relation unless Thread.current[:promo_digest_in_digest] == true
      return original_relation if user.nil?

      limit = extract_limit(opts)

      # ---------- DEBUG CONTEXT ----------
      digest_build_uuid = Thread.current[:promo_digest_build_uuid]
      for_digest_call_index = Thread.current[:promo_digest_for_digest_call_index]
      for_digest_since = Thread.current[:promo_digest_since]
      for_digest_opts_sanitized = Thread.current[:promo_digest_opts_sanitized]
      for_digest_callsite = Thread.current[:promo_digest_callsite]

      since_key = for_digest_since.respond_to?(:to_i) ? for_digest_since.to_i : 0
      debug_dedupe_key = "u#{user.id}-s#{since_key}-l#{limit}"

      # ============================================================
      # Min-digests gate computed EARLY (applies to push + injections)
      # ============================================================
      min_digests_required = ::PromoDigestSettings.min_digests_before_inject
      user_digest_count_val = 0
      is_skipped_min_digests = false
      if min_digests_required > 0
        user_digest_count_val = user_digest_count(user)
        is_skipped_min_digests = (user_digest_count_val < min_digests_required)
      end

      last_digest_sent_at = last_digest_sent_at_for_user(user)

      # ============================================================
      # PUSH OVERRIDE FLOW
      # ============================================================
      push_enabled = ::PromoDigestSettings.push_specific_enabled?
      push_tid_setting = ::PromoDigestSettings.push_specific_topic_id.to_i

      push_apply_percent = ::PromoDigestSettings.push_specific_apply_percent
      push_coinflip_passed = false

      push_cooldown_enabled = ::PromoDigestSettings.push_specific_skip_if_recent_push_enabled?
      push_cooldown_days = ::PromoDigestSettings.push_specific_skip_if_recent_push_days
      push_cooldown_blocked = false

      push_dynamic_enabled = ::PromoDigestSettings.push_specific_dynamic_enabled?
      push_dynamic_tags = ::PromoDigestSettings.push_specific_dynamic_tags

      push_applied = false
      push_source = nil
      push_selected_topic_id = nil
      push_dynamic_debug = {}

      push_skip_reason = nil

      if push_enabled
        if is_skipped_min_digests
          push_skip_reason = "min_digests_gate"
        else
          if push_cooldown_enabled && push_cooldown_days.to_i > 0
            if push_received_within_days?(user, push_cooldown_days)
              push_cooldown_blocked = true
              push_skip_reason = "recent_push_cooldown"
            end
          end

          if !push_cooldown_blocked
            if push_apply_percent.to_i <= 0
              push_skip_reason = "coinflip"
            else
              push_coinflip_passed = (push_apply_percent.to_i >= 100) || (rand(100) < push_apply_percent.to_i)
              if !push_coinflip_passed
                push_skip_reason = "coinflip"
              else
                # (1) Explicit topic id via settings (SUPERPUSH-aware)
                if push_tid_setting > 0
                  guardian = Guardian.new(user)

                  watched_all_for_push = watched_category_ids_for_user_always(user)
                  sp_ctx = superpush_context_for_user(user, watched_all_for_push)
                  sp_active = sp_ctx[:active]
                  sp_watched_ids = sp_ctx[:used_category_ids]

                  row =
                    Topic
                      .visible
                      .secured(guardian)
                      .where(id: push_tid_setting)
                      .limit(1)
                      .pluck(:id, :category_id)
                      .first

                  if row
                    tid = row[0].to_i
                    cid = row[1].to_i

                    if sp_active
                      if sp_watched_ids.present? && sp_watched_ids.include?(cid)
                        push_selected_topic_id = tid
                        push_source = "settings_topic_id_superpush"
                        push_dynamic_debug ||= {}
                        push_dynamic_debug["superpush"] = sp_ctx
                      end
                    else
                      push_selected_topic_id = tid
                      push_source = "settings_topic_id"
                      push_dynamic_debug ||= {}
                      push_dynamic_debug["superpush"] = sp_ctx if sp_ctx.present?
                    end
                  end
                end

                # (2) Dynamic picker (if no explicit visible topic id)
                if push_selected_topic_id.nil? && push_dynamic_enabled
                  picked_id, src, dyn_debug =
                    pick_dynamic_push_topic_id(
                      user,
                      original_relation,
                      limit: limit,
                      last_digest_sent_at: last_digest_sent_at
                    )
                  if picked_id.to_i > 0
                    push_selected_topic_id = picked_id.to_i
                    push_source = src
                    push_dynamic_debug = dyn_debug || {}
                  end
                end

                if push_selected_topic_id.to_i > 0
                  push_applied = true

                  final_ids = [push_selected_topic_id.to_i]
                  original_ids = original_relation.limit(limit).pluck(:id).map(&:to_i).reject(&:zero?)

                  persist_last_digest_topics(user, final_ids)
                  persist_last_digest_first_topic(user, final_ids.first)
                  persist_pushed_topic_history(user, final_ids.first)

                  enqueue_summary_post(
                    user: user,

                    promo_tag: "",
                    promo_tag_found: false,
                    promo_tag_id: nil,
                    promo_tag_total_topics: 0,
                    promo_tag_ids: [],
                    promo_tag_names: [],
                    first_injected_tag_name: nil,

                    original_ids: original_ids,
                    tagged_ids_in_original: [],
                    injected_ids: [],
                    final_ids: final_ids,

                    original_topics_matched_tags: {},
                    injected_topics_matched_tags: {},

                    is_skipped_haspromo: false,
                    is_skipped_coinflip: false,
                    is_skipped_min_digests: is_skipped_min_digests,
                    min_digests_required: min_digests_required,
                    user_digest_count: user_digest_count_val,
                    replaced_indices: [],
                    attempted_replace: false,
                    candidate_pool_count: 0,
                    visible_pool_count: 0,
                    watched_category_ids: [],
                    watched_filter_applied: false,
                    forced_first_applied: false,
                    first_topic_id_before_force: final_ids.first,
                    first_topic_id_after_force: final_ids.first,
                    first_topic_was_watched_before_force: false,
                    first_topic_was_watched_after_force: false,
                    last_digest_sent_at: last_digest_sent_at,
                    created_after_last_digest_filter_enabled: ::PromoDigestSettings.filter_promo_topics_created_after_last_digest?,
                    created_after_last_digest_filter_applied: false,
                    promo_pick_mode: ::PromoDigestSettings.promo_pick_mode,
                    digest_list_candidates_count: 0,
                    digest_list_visible_count: 0,
                    digest_list_picked: [],
                    fallback_picked: [],
                    used_fallback_outside_digest: false,
                    user_watched_category_ids: watched_category_ids_for_user(user),

                    no_watched_shuffle_enabled: ::PromoDigestSettings.shuffle_topics_if_no_watched_categories?,
                    no_watched_shuffle_applied: false,
                    no_watched_shuffle_top_n: ::PromoDigestSettings.shuffle_topics_if_no_watched_top_n,
                    no_watched_shuffle_coinflip_percent: ::PromoDigestSettings.shuffle_topics_if_no_watched_coinflip_percent,

                    watched_percent_enforcer_applied: false,
                    watched_percent_debug: {},

                    superpromo_tag: "",
                    superpromo_tag_ids: [],
                    superpromo_injected_ids: [],
                    superpromo_attempted_replace: false,
                    superpromo_replace_indices: [],
                    superpromo_is_skipped_hastag: false,
                    superpromo_is_skipped_coinflip: false,
                    superpromo_candidate_pool_count: 0,
                    superpromo_visible_pool_count: 0,
                    superpromo_watched_category_ids: [],
                    superpromo_watched_filter_applied: false,
                    superpromo_pick_mode: ::PromoDigestSettings.superpromo_pick_mode,
                    superpromo_digest_list_candidates_count: 0,
                    superpromo_digest_list_visible_count: 0,
                    superpromo_digest_list_picked: [],
                    superpromo_fallback_picked: [],
                    superpromo_used_fallback_outside_digest: false,
                    superpromo_created_after_enabled: ::PromoDigestSettings.superpromo_filter_topics_created_after_last_digest?,
                    superpromo_created_after_applied: false,

                    hardsale_tag: "",
                    hardsale_tag_ids: [],
                    hardsale_injected_ids: [],
                    hardsale_attempted_replace: false,
                    hardsale_replace_indices: [],
                    hardsale_is_skipped_hastag: false,
                    hardsale_is_skipped_coinflip: false,
                    hardsale_candidate_pool_count: 0,
                    hardsale_visible_pool_count: 0,
                    hardsale_watched_category_ids: [],
                    hardsale_watched_filter_applied: false,
                    hardsale_pick_mode: ::PromoDigestSettings.hardsale_pick_mode,
                    hardsale_digest_list_candidates_count: 0,
                    hardsale_digest_list_visible_count: 0,
                    hardsale_digest_list_picked: [],
                    hardsale_fallback_picked: [],
                    hardsale_used_fallback_outside_digest: false,
                    hardsale_created_after_enabled: ::PromoDigestSettings.hardsale_filter_topics_created_after_last_digest?,
                    hardsale_created_after_applied: false,

                    debug_digest_build_uuid: digest_build_uuid,
                    debug_for_digest_call_index: for_digest_call_index,
                    debug_for_digest_since: (for_digest_since.respond_to?(:utc) ? for_digest_since.utc.iso8601 : for_digest_since),
                    debug_for_digest_opts: for_digest_opts_sanitized,
                    debug_for_digest_callsite: for_digest_callsite,
                    debug_dedupe_key: debug_dedupe_key,

                    push_specific_enabled: push_enabled,
                    push_specific_topic_id: push_tid_setting,
                    push_specific_applied: push_applied,
                    push_specific_source: push_source,
                    push_specific_selected_topic_id: push_selected_topic_id,
                    push_specific_apply_percent: push_apply_percent,
                    push_specific_coinflip_passed: push_coinflip_passed,
                    push_specific_skip_reason: push_skip_reason,
                    push_specific_cooldown_enabled: push_cooldown_enabled,
                    push_specific_cooldown_days: push_cooldown_days,
                    push_specific_cooldown_blocked: push_cooldown_blocked,
                    push_specific_dynamic_enabled: push_dynamic_enabled,
                    push_specific_dynamic_tags: push_dynamic_tags,
                    push_specific_dynamic_debug: push_dynamic_debug
                  )

                  return build_ordered_relation(user, final_ids)
                end
              end
            end
          end
        end
      end

      # ------------------------------------------------------------
      # Normal flow (existing behavior) — UNCHANGED FROM YOUR FILE
      # ------------------------------------------------------------
      original_ids = original_relation.limit(limit).pluck(:id)
      original_ids = Array(original_ids).map(&:to_i).reject(&:zero?)

      promo_tags = ::PromoDigestSettings.promo_tags
      promo_tag_for_payload = promo_tags.join(", ")

      tags = promo_tags.map { |t| find_tag_by_name_ci(t) }.compact
      tag_ids = tags.map(&:id).compact.uniq

      superpromo_tags = ::PromoDigestSettings.superpromo_tags
      superpromo_tag_for_payload = superpromo_tags.join(", ")
      superpromo_tag_models = superpromo_tags.map { |t| find_tag_by_name_ci(t) }.compact
      superpromo_tag_ids = superpromo_tag_models.map(&:id).compact.uniq

      hardsale_tags = ::PromoDigestSettings.hardsale_tags
      hardsale_tag_for_payload = hardsale_tags.join(", ")
      hardsale_tag_models = hardsale_tags.map { |t| find_tag_by_name_ci(t) }.compact
      hardsale_tag_ids = hardsale_tag_models.map(&:id).compact.uniq

      user_watched_category_ids = watched_category_ids_for_user(user)

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

      min_position = ::PromoDigestSettings.min_position

      has_tagged_in_top =
        if original_ids.present?
          original_ids.first(min_position).any? { |tid| tagged_ids_set.include?(tid) }
        else
          false
        end

      skip_percent = ::PromoDigestSettings.coinflip_skip_percent

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

      created_after_last_digest_filter_enabled = ::PromoDigestSettings.filter_promo_topics_created_after_last_digest?
      created_after_last_digest_filter_applied = (created_after_last_digest_filter_enabled && last_digest_sent_at.present?)

      promo_pick_mode = ::PromoDigestSettings.promo_pick_mode
      prefer_digest_list_mode = (promo_pick_mode == "prefer_digest_list")

      digest_list_candidates_count = 0
      digest_list_visible_count = 0
      digest_list_picked = []
      fallback_picked = []
      used_fallback_outside_digest = false

      no_watched_shuffle_enabled = ::PromoDigestSettings.shuffle_topics_if_no_watched_categories?
      no_watched_shuffle_top_n   = ::PromoDigestSettings.shuffle_topics_if_no_watched_top_n
      no_watched_shuffle_coinflip_percent = ::PromoDigestSettings.shuffle_topics_if_no_watched_coinflip_percent
      no_watched_shuffle_applied = false

      watched_percent_enforcer_applied = false
      watched_percent_debug = {}

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

      superpromo_pick_mode = ::PromoDigestSettings.superpromo_pick_mode
      superpromo_prefer_digest_list_mode = (superpromo_pick_mode == "prefer_digest_list")

      superpromo_digest_list_candidates_count = 0
      superpromo_digest_list_visible_count = 0
      superpromo_digest_list_picked = []
      superpromo_fallback_picked = []
      superpromo_used_fallback_outside_digest = false

      superpromo_created_after_enabled = ::PromoDigestSettings.superpromo_filter_topics_created_after_last_digest?
      superpromo_created_after_applied = (superpromo_created_after_enabled && last_digest_sent_at.present?)

      hardsale_has_tagged_in_top = false
      hardsale_is_skipped_hastag = false
      hardsale_is_skipped_coinflip = false
      hardsale_attempted_replace = false
      hardsale_replace_indices = []
      hardsale_injected_ids = []

      hardsale_candidate_pool_count = 0
      hardsale_visible_pool_count = 0
      hardsale_watched_category_ids = []
      hardsale_watched_filter_applied = false

      hardsale_pick_mode = ::PromoDigestSettings.hardsale_pick_mode
      hardsale_prefer_digest_list_mode = (hardsale_pick_mode == "prefer_digest_list")

      hardsale_digest_list_candidates_count = 0
      hardsale_digest_list_visible_count = 0
      hardsale_digest_list_picked = []
      hardsale_fallback_picked = []
      hardsale_used_fallback_outside_digest = false

      hardsale_created_after_enabled = ::PromoDigestSettings.hardsale_filter_topics_created_after_last_digest?
      hardsale_created_after_applied = (hardsale_created_after_enabled && last_digest_sent_at.present?)

      # ============================================================
      # Promo injection block (blocked by min-digests gate)
      # Also gated by SiteSetting: promo_digest_injector_regular_enabled
      # ============================================================
      if ::PromoDigestSettings.regular_injection_enabled? &&
         !is_skipped_min_digests && !is_skipped_haspromo && original_ids.present? && tag_ids.present?

        if rand(100) < skip_percent
          is_skipped_coinflip = true
        else
          replace_within_top_n = ::PromoDigestSettings.replace_within_top_n
          replace_count = ::PromoDigestSettings.replace_count

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
      if ::PromoDigestSettings.superpromo_enabled? &&
         !is_skipped_min_digests &&
         final_ids.present? && superpromo_tag_ids.present?

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

        superpromo_min_position = ::PromoDigestSettings.superpromo_min_position

        superpromo_has_tagged_in_top =
          if final_ids.present?
            final_ids.first(superpromo_min_position).any? { |tid| superpromo_tagged_ids_set.include?(tid) }
          else
            false
          end

        superpromo_is_skipped_hastag = superpromo_has_tagged_in_top

        superpromo_skip_percent = ::PromoDigestSettings.superpromo_coinflip_skip_percent

        if !superpromo_is_skipped_hastag
          if rand(100) < superpromo_skip_percent
            superpromo_is_skipped_coinflip = true
          else
            within_top_n = ::PromoDigestSettings.superpromo_replace_within_top_n
            sp_replace_count = ::PromoDigestSettings.superpromo_replace_count

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
                    digest_ids: final_ids,
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
      # HARDSALE injection block (runs THIRD, independent)
      # ============================================================
      if ::PromoDigestSettings.hardsale_enabled? &&
         !is_skipped_min_digests &&
         final_ids.present? && hardsale_tag_ids.present?

        hardsale_tagged_ids_set =
          begin
            w3 = watched_category_ids_for_user_hardsale(user)
            if w3.present?
              fetch_tagged_topic_ids_any_tag_in_categories(final_ids, hardsale_tag_ids, w3).to_set
            else
              fetch_tagged_topic_ids_any_tag(final_ids, hardsale_tag_ids).to_set
            end
          rescue
            Set.new
          end

        hardsale_min_position = ::PromoDigestSettings.hardsale_min_position

        hardsale_has_tagged_in_top =
          if final_ids.present?
            final_ids.first(hardsale_min_position).any? { |tid| hardsale_tagged_ids_set.include?(tid) }
          else
            false
          end

        hardsale_is_skipped_hastag = hardsale_has_tagged_in_top

        hardsale_skip_percent = ::PromoDigestSettings.hardsale_coinflip_skip_percent

        if !hardsale_is_skipped_hastag
          if rand(100) < hardsale_skip_percent
            hardsale_is_skipped_coinflip = true
          else
            within_top_n = ::PromoDigestSettings.hardsale_replace_within_top_n
            hs_replace_count = ::PromoDigestSettings.hardsale_replace_count

            window = [within_top_n, final_ids.length].min
            if window > 0 && hs_replace_count > 0
              hardsale_attempted_replace = true
              hardsale_replace_indices = (0...window).to_a.sample([hs_replace_count, window].min)

              if hardsale_prefer_digest_list_mode
                tmp_ids = final_ids.dup

                eligible_set, cand_ct, vis_ct, watched_ids, watched_applied =
                  eligible_hardsale_set_within_digest_list(
                    user,
                    tag_ids: hardsale_tag_ids,
                    digest_ids: final_ids,
                    created_after: (hardsale_created_after_applied ? last_digest_sent_at : nil)
                  )

                hardsale_digest_list_candidates_count = cand_ct
                hardsale_digest_list_visible_count = vis_ct
                hardsale_watched_category_ids = watched_ids
                hardsale_watched_filter_applied = watched_applied

                _satisfied, swapped_in_ids, remaining_indices =
                  swap_eligible_promos_into_indices(
                    tmp_ids,
                    hardsale_replace_indices,
                    eligible_set
                  )

                hardsale_digest_list_picked = swapped_in_ids.dup

                if remaining_indices.any?
                  remaining_need = remaining_indices.length

                  fallback_ids, cand_b, vis_b, watched_b, watched_applied_b =
                    pick_random_hardsale_topic_ids(
                      user,
                      tag_ids: hardsale_tag_ids,
                      exclude_ids: tmp_ids,
                      limit: remaining_need,
                      created_after: (hardsale_created_after_applied ? last_digest_sent_at : nil)
                    )

                  hardsale_used_fallback_outside_digest = fallback_ids.present?
                  hardsale_fallback_picked = fallback_ids.dup

                  hardsale_candidate_pool_count = cand_ct + cand_b
                  hardsale_visible_pool_count = vis_ct + vis_b

                  hardsale_watched_category_ids = watched_b
                  hardsale_watched_filter_applied = watched_applied_b

                  if fallback_ids.length == remaining_need
                    remaining_indices.each_with_index do |idx, j|
                      tmp_ids[idx] = fallback_ids[j]
                    end

                    final_ids = tmp_ids
                    hardsale_injected_ids = swapped_in_ids + fallback_ids
                  else
                    hardsale_injected_ids = []
                    hardsale_replace_indices = []
                  end
                else
                  hardsale_candidate_pool_count = cand_ct
                  hardsale_visible_pool_count = vis_ct
                  final_ids = tmp_ids
                  hardsale_injected_ids = swapped_in_ids
                end
              else
                hardsale_injected_ids, hardsale_candidate_pool_count, hardsale_visible_pool_count,
                  hardsale_watched_category_ids, hardsale_watched_filter_applied =
                    pick_random_hardsale_topic_ids(
                      user,
                      tag_ids: hardsale_tag_ids,
                      exclude_ids: final_ids,
                      limit: hardsale_replace_indices.length,
                      created_after: (hardsale_created_after_applied ? last_digest_sent_at : nil)
                    )

                if hardsale_injected_ids.length == hardsale_replace_indices.length
                  hardsale_replace_indices.each_with_index do |idx, j|
                    final_ids[idx] = hardsale_injected_ids[j]
                  end
                else
                  hardsale_injected_ids = []
                  hardsale_replace_indices = []
                end
              end
            end
          end
        end
      end

      # ============================================================
      # Enforce minimum % watched-category topics (AFTER injections)
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

        hardsale_tag: hardsale_tag_for_payload,
        hardsale_tag_ids: hardsale_tag_ids,
        hardsale_injected_ids: hardsale_injected_ids,
        hardsale_attempted_replace: hardsale_attempted_replace,
        hardsale_replace_indices: hardsale_replace_indices,
        hardsale_is_skipped_hastag: hardsale_is_skipped_hastag,
        hardsale_is_skipped_coinflip: hardsale_is_skipped_coinflip,
        hardsale_candidate_pool_count: hardsale_candidate_pool_count,
        hardsale_visible_pool_count: hardsale_visible_pool_count,
        hardsale_watched_category_ids: hardsale_watched_category_ids,
        hardsale_watched_filter_applied: hardsale_watched_filter_applied,
        hardsale_pick_mode: hardsale_pick_mode,
        hardsale_digest_list_candidates_count: hardsale_digest_list_candidates_count,
        hardsale_digest_list_visible_count: hardsale_digest_list_visible_count,
        hardsale_digest_list_picked: hardsale_digest_list_picked,
        hardsale_fallback_picked: hardsale_fallback_picked,
        hardsale_used_fallback_outside_digest: hardsale_used_fallback_outside_digest,
        hardsale_created_after_enabled: hardsale_created_after_enabled,
        hardsale_created_after_applied: hardsale_created_after_applied,

        debug_digest_build_uuid: digest_build_uuid,
        debug_for_digest_call_index: for_digest_call_index,
        debug_for_digest_since: (for_digest_since.respond_to?(:utc) ? for_digest_since.utc.iso8601 : for_digest_since),
        debug_for_digest_opts: for_digest_opts_sanitized,
        debug_for_digest_callsite: for_digest_callsite,
        debug_dedupe_key: debug_dedupe_key,

        push_specific_enabled: push_enabled,
        push_specific_topic_id: push_tid_setting,
        push_specific_applied: false,
        push_specific_source: push_source,
        push_specific_selected_topic_id: push_selected_topic_id,
        push_specific_apply_percent: push_apply_percent,
        push_specific_coinflip_passed: push_coinflip_passed,
        push_specific_skip_reason: push_skip_reason,
        push_specific_cooldown_enabled: push_cooldown_enabled,
        push_specific_cooldown_days: push_cooldown_days,
        push_specific_cooldown_blocked: push_cooldown_blocked,
        push_specific_dynamic_enabled: push_dynamic_enabled,
        push_specific_dynamic_tags: push_dynamic_tags,
        push_specific_dynamic_debug: push_dynamic_debug
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
      l = ::PromoDigestSettings.default_digest_limit if l.nil? || l <= 0
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
    def self.notification_levels(include_first_post:)
      levels = []
      if defined?(CategoryUser) && CategoryUser.respond_to?(:notification_levels)
        nl = CategoryUser.notification_levels
        levels << (nl[:watching] || 3)
        levels << (nl[:watching_first_post] || 4) if include_first_post
      else
        levels = include_first_post ? [3, 4] : [3]
      end
      levels
    end

    def self.watched_category_ids_for_user(user)
      return [] unless ::PromoDigestSettings.use_watched_categories?
      return [] if user.nil?

      levels = notification_levels(include_first_post: ::PromoDigestSettings.include_watching_first_post?)
      CategoryUser.where(user_id: user.id, notification_level: levels).pluck(:category_id)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] watched_category_ids_for_user failed: #{e.class}: #{e.message}")
      []
    end

    def self.watched_category_ids_for_user_always(user)
      return [] if user.nil?
      levels = notification_levels(include_first_post: ::PromoDigestSettings.include_watching_first_post?)
      CategoryUser.where(user_id: user.id, notification_level: levels).pluck(:category_id)
    rescue
      []
    end

    def self.watched_category_ids_for_user_superpromo(user)
      return [] unless ::PromoDigestSettings.superpromo_use_watched_categories?
      return [] if user.nil?

      levels = notification_levels(include_first_post: ::PromoDigestSettings.superpromo_include_watching_first_post?)
      CategoryUser.where(user_id: user.id, notification_level: levels).pluck(:category_id)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] watched_category_ids_for_user_superpromo failed: #{e.class}: #{e.message}")
      []
    end

    def self.watched_category_ids_for_user_hardsale(user)
      return [] unless ::PromoDigestSettings.hardsale_use_watched_categories?
      return [] if user.nil?

      levels = notification_levels(include_first_post: ::PromoDigestSettings.hardsale_include_watching_first_post?)
      CategoryUser.where(user_id: user.id, notification_level: levels).pluck(:category_id)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] watched_category_ids_for_user_hardsale failed: #{e.class}: #{e.message}")
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
      return ids unless ::PromoDigestSettings.force_first_topic_from_watched_category?

      pct = ::PromoDigestSettings.force_first_topic_watched_coinflip_percent
      return ids if pct == 0
      return ids if pct < 100 && rand(100) >= pct

      watched_ids = watched_category_ids_for_user(user)
      return ids if watched_ids.blank?

      guardian = Guardian.new(user)

      randomize_even_if_already_watched = ::PromoDigestSettings.force_first_topic_randomize_even_if_already_watched?

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

      lookahead = ::PromoDigestSettings.force_first_topic_lookahead
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

      require_created_after = ::PromoDigestSettings.force_first_topic_require_created_after_last_digest?
      soft_fallback = ::PromoDigestSettings.force_first_topic_soft_fallback?

      last_ts = nil
      last_ts = last_digest_sent_at_for_user(user) if require_created_after

      top_n = ::PromoDigestSettings.force_first_topic_random_top_n

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

      if ::PromoDigestSettings.filter_promo_topics_created_after_last_digest? && created_after.present?
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

      if ::PromoDigestSettings.superpromo_filter_topics_created_after_last_digest? && created_after.present?
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

    def self.eligible_hardsale_set_within_digest_list(user, tag_ids:, digest_ids:, created_after: nil)
      return [Set.new, 0, 0, [], false] if user.nil?
      return [Set.new, 0, 0, [], false] if tag_ids.blank?
      return [Set.new, 0, 0, [], false] if digest_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user_hardsale(user)
      watched_filter_applied = watched_ids.present?

      scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_ids, topic_id: digest_ids })
          .distinct

      scope = scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestSettings.hardsale_filter_topics_created_after_last_digest? && created_after.present?
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
      Rails.logger.warn("[#{PLUGIN_NAME}] eligible_hardsale_set_within_digest_list failed: #{e.class}: #{e.message}")
      [Set.new, 0, 0, [], false]
    end

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

      if ::PromoDigestSettings.filter_promo_topics_created_after_last_digest? && created_after.present?
        topic_tag_scope = topic_tag_scope.where("topics.created_at > ?", created_after)
      end

      scan_cap = ::PromoDigestSettings.promo_candidate_scan_cap

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

      if ::PromoDigestSettings.superpromo_filter_topics_created_after_last_digest? && created_after.present?
        topic_tag_scope = topic_tag_scope.where("topics.created_at > ?", created_after)
      end

      scan_cap = ::PromoDigestSettings.superpromo_candidate_scan_cap

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

    def self.pick_random_hardsale_topic_ids(user, tag_ids:, exclude_ids:, limit:, created_after: nil)
      return [[], 0, 0, [], false] if limit.to_i <= 0
      return [[], 0, 0, [], false] if tag_ids.blank?

      guardian = Guardian.new(user)

      watched_ids = watched_category_ids_for_user_hardsale(user)
      watched_filter_applied = watched_ids.present?

      topic_tag_scope =
        TopicTag
          .joins(:topic)
          .where(topic_tags: { tag_id: tag_ids })
          .where.not(topic_tags: { topic_id: exclude_ids })
          .distinct

      topic_tag_scope = topic_tag_scope.where(topics: { category_id: watched_ids }) if watched_filter_applied

      if ::PromoDigestSettings.hardsale_filter_topics_created_after_last_digest? && created_after.present?
        topic_tag_scope = topic_tag_scope.where("topics.created_at > ?", created_after)
      end

      scan_cap = ::PromoDigestSettings.hardsale_candidate_scan_cap

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
      Rails.logger.warn("[#{PLUGIN_NAME}] pick_random_hardsale_topic_ids failed: #{e.class}: #{e.message}")
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
      return ids if ::PromoDigestSettings.send_ids_only?
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

      hardsale_tag:,
      hardsale_tag_ids:,
      hardsale_injected_ids:,
      hardsale_attempted_replace:,
      hardsale_replace_indices:,
      hardsale_is_skipped_hastag:,
      hardsale_is_skipped_coinflip:,
      hardsale_candidate_pool_count:,
      hardsale_visible_pool_count:,
      hardsale_watched_category_ids:,
      hardsale_watched_filter_applied:,
      hardsale_pick_mode:,
      hardsale_digest_list_candidates_count:,
      hardsale_digest_list_visible_count:,
      hardsale_digest_list_picked:,
      hardsale_fallback_picked:,
      hardsale_used_fallback_outside_digest:,
      hardsale_created_after_enabled:,
      hardsale_created_after_applied:,

      debug_digest_build_uuid:,
      debug_for_digest_call_index:,
      debug_for_digest_since:,
      debug_for_digest_opts:,
      debug_for_digest_callsite:,
      debug_dedupe_key:,

      push_specific_enabled:,
      push_specific_topic_id:,
      push_specific_applied:,
      push_specific_source:,
      push_specific_selected_topic_id:,
      push_specific_apply_percent:,
      push_specific_coinflip_passed:,
      push_specific_skip_reason:,
      push_specific_cooldown_enabled:,
      push_specific_cooldown_days:,
      push_specific_cooldown_blocked:,
      push_specific_dynamic_enabled:,
      push_specific_dynamic_tags:,
      push_specific_dynamic_debug:
    )
      endpoint = ::PromoDigestSettings.endpoint_url
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

          push_specific: {
            enabled: push_specific_enabled,
            settings_topic_id: push_specific_topic_id,
            applied: push_specific_applied,
            source: push_specific_source,
            selected_topic_id: push_specific_selected_topic_id,
            apply_percent: push_specific_apply_percent,
            coinflip_passed: push_specific_coinflip_passed,
            skip_reason: push_specific_skip_reason,
            cooldown_enabled: push_specific_cooldown_enabled,
            cooldown_days: push_specific_cooldown_days,
            cooldown_blocked: push_specific_cooldown_blocked,
            dynamic_enabled: push_specific_dynamic_enabled,
            dynamic_tags: push_specific_dynamic_tags,
            dynamic_debug: push_specific_dynamic_debug,
            pushed_history_field: ::PromoDigestSettings.push_specific_pushed_history_field,
            pushed_history_max: ::PromoDigestSettings.push_specific_pushed_history_max
          },

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
          watched_categories_mode: ::PromoDigestSettings.use_watched_categories?,
          watched_filter_applied: watched_filter_applied,

          watched_percent_enforcer_enabled: ::PromoDigestSettings.enforce_min_watched_category_percent?,
          watched_percent_enforcer_applied: watched_percent_enforcer_applied,
          watched_percent_enforcer_debug: watched_percent_debug,

          forced_first_topic_from_watched_category_enabled: ::PromoDigestSettings.force_first_topic_from_watched_category?,
          forced_first_topic_coinflip_percent: ::PromoDigestSettings.force_first_topic_watched_coinflip_percent,
          force_first_topic_randomize_even_if_already_watched: ::PromoDigestSettings.force_first_topic_randomize_even_if_already_watched?,
          force_first_topic_random_top_n: ::PromoDigestSettings.force_first_topic_random_top_n,
          forced_first_topic_require_created_after_last_digest: ::PromoDigestSettings.force_first_topic_require_created_after_last_digest?,
          forced_first_topic_soft_fallback: ::PromoDigestSettings.force_first_topic_soft_fallback?,
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

          regular_injection_enabled: ::PromoDigestSettings.regular_injection_enabled?,

          superpromo: {
            enabled: ::PromoDigestSettings.superpromo_enabled?,
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
            watched_categories_mode: ::PromoDigestSettings.superpromo_use_watched_categories?,
            watched_filter_applied: superpromo_watched_filter_applied,
            pick_mode: superpromo_pick_mode,
            digest_list_candidates_count: superpromo_digest_list_candidates_count,
            digest_list_visible_count: superpromo_digest_list_visible_count,
            digest_list_picked: superpromo_digest_list_picked,
            used_fallback_outside_digest: superpromo_used_fallback_outside_digest,
            fallback_picked: superpromo_fallback_picked,
            created_after_last_digest_filter_enabled: superpromo_created_after_enabled,
            created_after_last_digest_filter_applied: superpromo_created_after_applied
          },

          hardsale: {
            enabled: ::PromoDigestSettings.hardsale_enabled?,
            tag: hardsale_tag,
            tag_ids: hardsale_tag_ids,
            injected_topic_ids: hardsale_injected_ids,
            attempted_replace: hardsale_attempted_replace,
            replaced_indices: hardsale_replace_indices,
            is_skipped_hastag: hardsale_is_skipped_hastag,
            is_skipped_coinflip: hardsale_is_skipped_coinflip,
            candidate_pool_count: hardsale_candidate_pool_count,
            visible_pool_count: hardsale_visible_pool_count,
            watched_category_ids: hardsale_watched_category_ids,
            watched_categories_mode: ::PromoDigestSettings.hardsale_use_watched_categories?,
            watched_filter_applied: hardsale_watched_filter_applied,
            pick_mode: hardsale_pick_mode,
            digest_list_candidates_count: hardsale_digest_list_candidates_count,
            digest_list_visible_count: hardsale_digest_list_visible_count,
            digest_list_picked: hardsale_digest_list_picked,
            used_fallback_outside_digest: hardsale_used_fallback_outside_digest,
            fallback_picked: hardsale_fallback_picked,
            created_after_last_digest_filter_enabled: hardsale_created_after_enabled,
            created_after_last_digest_filter_applied: hardsale_created_after_applied
          }
        }
      }

      Jobs.enqueue(
        :promo_digest_send_summary,
        endpoint_url: endpoint,
        secret: ::PromoDigestSettings.secret_header_value,
        log_post_results: ::PromoDigestSettings.log_post_results?,
        open_timeout: ::PromoDigestSettings.http_open_timeout,
        read_timeout: ::PromoDigestSettings.http_read_timeout,
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
  # ============================================================
  module ::PromoDigestForDigestOverride
    def for_digest(user, since, opts = nil)
      if Thread.current[:promo_digest_in_digest] == true
        Thread.current[:promo_digest_for_digest_call_index] =
          (Thread.current[:promo_digest_for_digest_call_index].to_i + 1)

        Thread.current[:promo_digest_since] = since
        Thread.current[:promo_digest_opts_sanitized] = ::PromoDigestInjector.sanitize_opts_for_debug(opts)

        depth = ::PromoDigestSettings.debug_callsite_depth
        Thread.current[:promo_digest_callsite] = caller_locations(0, depth).map(&:to_s)
      end

      rel = super(user, since, opts)

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
