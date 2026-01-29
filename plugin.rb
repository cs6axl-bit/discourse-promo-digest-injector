# frozen_string_literal: true

enabled_site_setting :promo_digest_enabled

PLUGIN_NAME = "discourse-promo-digest-injector"

after_initialize do
  require "net/http"
  require "uri"
  require "json"
  require "set"

  module ::PromoDigestInjector
    FIELD_NAME = "has_promo_comment"

    # -------------------------
    # Public entrypoint
    # -------------------------
    def self.maybe_adjust_digest_topics(user, original_relation, opts)
      return original_relation unless SiteSetting.promo_digest_enabled
      return original_relation unless Thread.current[:promo_digest_in_digest] == true
      return original_relation if user.nil?

      limit = extract_limit(opts)
      original_ids = original_relation.limit(limit).pluck(:id)
      return original_relation if original_ids.blank?

      marked_ids_set = fetch_marked_topic_ids(original_ids).to_set

      # Condition A: if ANY marked topic is already in top N positions => do nothing
      min_position = SiteSetting.promo_digest_min_position.to_i
      min_position = 3 if min_position <= 0

      has_marked_in_top = original_ids.first(min_position).any? { |tid| marked_ids_set.include?(tid) }

      # Coinflip settings (integer percent, avoids float UI weirdness)
      skip_percent = SiteSetting.promo_digest_coinflip_skip_percent.to_i
      skip_percent = 30 if skip_percent <= 0
      skip_percent = 100 if skip_percent > 100

      is_skipped_haspromo  = has_marked_in_top
      is_skipped_coinflip  = false
      final_ids            = original_ids.dup

      injected_ids = []
      replace_indices = []

      if !is_skipped_haspromo
        # Condition fails => maybe coinflip
        if rand(100) < skip_percent
          is_skipped_coinflip = true
        else
          replace_within_top_n = SiteSetting.promo_digest_replace_within_top_n.to_i
          replace_within_top_n = 4 if replace_within_top_n <= 0

          replace_count = SiteSetting.promo_digest_replace_count.to_i
          replace_count = 2 if replace_count <= 0

          window = [replace_within_top_n, final_ids.length].min
          if window > 0 && replace_count > 0
            replace_indices = (0...window).to_a.sample([replace_count, window].min)

            injected_ids = pick_random_promo_topic_ids(user, exclude_ids: final_ids, limit: replace_indices.length)

            # Only inject if we got enough unique promo topics
            if injected_ids.length == replace_indices.length
              replace_indices.each_with_index do |idx, j|
                final_ids[idx] = injected_ids[j]
              end
            else
              # Not enough promo topics available => keep original
              injected_ids = []
              replace_indices = []
            end
          end
        end
      end

      # Always send summary (best-effort)
      send_summary_post(
        user: user,
        original_ids: original_ids,
        marked_ids_in_original: original_ids.select { |tid| marked_ids_set.include?(tid) },
        final_ids: final_ids,
        is_skipped_haspromo: is_skipped_haspromo,
        is_skipped_coinflip: is_skipped_coinflip,
        injected_ids: injected_ids,
        replaced_indices: replace_indices
      )

      # Build a new relation preserving EXACT final ordering
      build_ordered_relation(user, final_ids)
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] error in maybe_adjust_digest_topics: #{e.class}: #{e.message}")
      original_relation
    end

    # -------------------------
    # Helpers
    # -------------------------
    def self.extract_limit(opts)
      l = opts.is_a?(Hash) ? opts[:limit] : nil
      l = l.to_i if l
      l = 40 if l.nil? || l <= 0
      l
    end

    def self.fetch_marked_topic_ids(topic_ids)
      return [] if topic_ids.blank?

      TopicCustomField
        .where(topic_id: topic_ids, name: FIELD_NAME, value: "1")
        .pluck(:topic_id)
    end

    def self.pick_random_promo_topic_ids(user, exclude_ids:, limit:)
      return [] if limit.to_i <= 0

      guardian = Guardian.new(user)

      # Pull some random candidates from the custom field table first
      candidate_ids =
        TopicCustomField
          .where(name: FIELD_NAME, value: "1")
          .where.not(topic_id: exclude_ids)
          .order(Arel.sql("RANDOM()"))
          .limit(200)
          .pluck(:topic_id)

      return [] if candidate_ids.blank?

      # Filter to topics user can see; then randomize again and take what we need
      Topic
        .visible
        .secured(guardian)
        .where(id: candidate_ids)
        .where.not(id: exclude_ids)
        .order(Arel.sql("RANDOM()"))
        .limit(limit)
        .pluck(:id)
    end

    def self.build_ordered_relation(user, ids)
      return Topic.none if ids.blank?

      guardian = Guardian.new(user)

      # CASE-based ordering preserves the array order
      case_sql = +"CASE topics.id "
      ids.each_with_index do |id, idx|
        case_sql << "WHEN #{id.to_i} THEN #{idx} "
      end
      case_sql << "END"

      Topic
        .visible
        .secured(guardian)
        .where(id: ids)
        .order(Arel.sql(case_sql))
    end

    def self.serialize_topics(ids)
      return [] if ids.blank?

      topics = Topic.where(id: ids).pluck(:id, :title, :slug, :category_id).map do |id, title, slug, category_id|
        {
          id: id,
          title: title,
          slug: slug,
          category_id: category_id,
          url: "#{Discourse.base_url}#{Topic.slug_path(slug, id)}"
        }
      end

      # keep same order as ids
      idx = {}
      ids.each_with_index { |tid, i| idx[tid] = i }
      topics.sort_by { |t| idx[t[:id]] || 999_999 }
    end

    def self.send_summary_post(user:, original_ids:, marked_ids_in_original:, final_ids:, is_skipped_haspromo:, is_skipped_coinflip:, injected_ids:, replaced_indices:)
      endpoint = SiteSetting.promo_digest_endpoint_url.to_s.strip
      return if endpoint.empty?

      uri = URI.parse(endpoint)

      now_iso = Time.now.utc.iso8601

      payload = {
        user_id: user.id,
        email: user.email,
        username: user.username,
        datetime_utc: now_iso,

        is_skipped_haspromo: is_skipped_haspromo,
        is_skipped_coinflip: is_skipped_coinflip,

        original_topics: serialize_topics(original_ids),
        marked_topics_in_original: serialize_topics(marked_ids_in_original),
        final_topics: serialize_topics(final_ids),

        debug: {
          injected_topic_ids: injected_ids,
          replaced_indices: replaced_indices
        }
      }

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == "https")
      http.open_timeout = 3
      http.read_timeout = 5

      req = Net::HTTP::Post.new(uri.request_uri)
      req["Content-Type"] = "application/json"
      req.body = payload.to_json

      res = http.request(req)
      Rails.logger.info("[#{PLUGIN_NAME}] summary POST => #{res.code}") if SiteSetting.promo_digest_log_posts
    rescue => e
      Rails.logger.warn("[#{PLUGIN_NAME}] failed summary POST: #{e.class}: #{e.message}")
    end
  end

  # ------------------------------------------------------------
  # 1) Wrap digest generation so our logic runs ONLY during digest
  # ------------------------------------------------------------
  module ::PromoDigestDigestWrapper
    def digest(user, opts = {})
      Thread.current[:promo_digest_in_digest] = true
      super
    ensure
      Thread.current[:promo_digest_in_digest] = false
    end
  end

  ::UserNotifications.prepend ::PromoDigestDigestWrapper

  # ------------------------------------------------------------
  # 2) Intercept Topic.for_digest and adjust topic ordering/choices
  # ------------------------------------------------------------
  module ::PromoDigestForDigestOverride
    def for_digest(user, since, opts = nil)
      rel = super(user, since, opts)
      ::PromoDigestInjector.maybe_adjust_digest_topics(user, rel, opts)
    end
  end

  ::Topic.singleton_class.prepend ::PromoDigestForDigestOverride
end
