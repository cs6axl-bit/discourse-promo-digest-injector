# frozen_string_literal: true
# name: discourse-promo-digest-injector
# about: Ensures digest includes tag-marked topics near the top (with optional random injection) and posts a run summary to an external endpoint (async, non-blocking)
# version: 1.0.3
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

    # PROMO SOURCE: Tag name on topics
    PROMO_TAG = "helpfull" # tag name (case-insensitive; Discourse stores tags lowercased)

    # If ANY promo-tagged topic exists in positions 1..MIN_POSITION => do nothing
    MIN_POSITION = 3

    # If above condition fails: in this % of cases do nothing
    COINFLIP_SKIP_PERCENT = 30 # 0..100

    # Otherwise: replace REPLACE_COUNT topics within the top REPLACE_WITHIN_TOP_N digest positions
    # using REPLACE_COUNT randomly chosen promo-tagged topics from the whole forum
    REPLACE_WITHIN_TOP_N = 4
    REPLACE_COUNT        = 2

    # Digest list limit (Discourse passes opts[:limit], but we keep a safe default)
    DEFAULT_DIGEST_LIMIT = 40

    # External summary endpoint (set empty to disable posting)
    ENDPOINT_URL = "https://ai.templetrends.com/digest_inject.php"

    # Optional secret header (leave empty to disable)
    SECRET_HEADER_VALUE = "" # sent as X-Promo-Postback-Secret

    # Log the HTTP status code for the summary POST (in Sidekiq job logs)
    LOG_POST_RESULTS = false

    # HTTP timeouts (seconds) - used in Sidekiq job
    HTTP_OPEN_TIMEOUT = 3
    HTTP_READ_TIMEOUT = 5

    # IMPORTANT: Sidekiq job args should not be huge. This keeps payload smaller.
    # Set false to send full topic objects (title/slug/url). Set true to send IDs only.
    SEND_IDS_ONLY = false
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
    def self.maybe_adjust_digest_topics(user, original_relation, opts)
      return original_relation unless ::PromoDigestConfig::ENABLED
      return original_relation unless Thread.current[:promo_digest_in_digest] == true
      return original_relation if user.nil?

      promo_tag = ::PromoDigestConfig::PROMO_TAG.to_s.strip.downcase
      return original_relation if promo_tag.empty?

      limit = extract_limit(opts)
      original_ids = original_relation.limit(limit).pluck(:id)
      return original_relation if original_ids.blank?

      tagged_ids_set = fetch_tagged_topic_ids(original_ids, promo_tag).to_set

      min_position = ::PromoDigestConfig::MIN_POSITION.to_i
      min_position = 3 if min_position <= 0

      # If any promo-tagged topic already appears in top MIN_POSITION => do nothing
      has_tagged_in_top = original_ids.first(min_position).any? { |tid| tagged_ids_set.include?(tid) }

      skip_percent = ::PromoDigestConfig::COINFLIP_SKIP_PERCENT.to_i
      skip_percent = 0 if skip_percent < 0
      skip_percent = 100 if skip_percent > 100

      is_skipped_haspromo = has_tagged_in_top
      is_skipped_coinflip = false

      final_ids = original_ids.dup
      injected_ids = []
      replace_indices = []

      if !is_skipped_haspromo
        # coinflip skip
        if rand(100) < skip_percent
          is_skipped_coinflip = true
        else
          replace_within_top_n = ::PromoDigestConfig::REPLACE_WITHIN_TOP_N.to_i
          replace_within_top_n = 4 if replace_within_top_n <= 0

          replace_count = ::PromoDigestConfig::REPLACE_COUNT.to_i
          replace_count = 2 if replace_count <= 0

          window = [replace_within_top_n, final_ids.length].min
          if window > 0 && replace_count > 0
            replace_indices = (0...window).to_a.sample([replace_count, window].min)

            injected_ids = pick_random_promo_topic_ids(
              user,
              promo_tag: promo_tag,
              exclude_ids: final_ids,
              limit: replace_indices.length
            )

            # Only inject if we got enough promo topics
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

      # Always best-effort ASYNC summary post (never blocks digest)
      enqueue_summary_post(
        user: user,
        promo_tag: promo_tag,
        original_ids: original_ids,
        tagged_ids_in_original: original_ids.select { |tid| tagged_ids_set.include?(tid) },
        injected_ids: injected_ids,
        final_ids: final_ids,
        is_skipped_haspromo: is_skipped_haspromo,
        is_skipped_coinflip: is_skipped_coinflip,
        replaced_indices: replace_indices
      )

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

    # Fetch which of the given topic_ids have the promo tag
    def self.fetch_tagged_topic_ids(topic_ids, promo_tag)
      return [] if topic_ids.blank?
      return [] if promo_tag.to_s.strip.empty?

      TopicTag
        .joins(:tag)
        .where(topic_id: topic_ids, tags: { name: promo_tag })
        .pluck(:topic_id)
    end

    def self.pick_random_promo_topic_ids(user, promo_tag:, exclude_ids:, limit:)
      return [] if limit.to_i <= 0
      return [] if promo_tag.to_s.strip.empty?

      guardian = Guardian.new(user)

      # Pull random candidates from topic_tags first (cheap-ish)
      candidate_ids =
        TopicTag
          .joins(:tag)
          .where(tags: { name: promo_tag })
          .where.not(topic_id: exclude_ids)
          .order(Arel.sql("RANDOM()"))
          .limit(300)
          .pluck(:topic_id)

      return [] if candidate_ids.blank?

      # Filter to topics user can see; then randomize and take needed count
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

    # Smaller payload option (IDs only)
    def self.pack_topics(ids)
      return [] if ids.blank?
      return ids if ::PromoDigestConfig::SEND_IDS_ONLY
      serialize_topics(ids)
    end

    def self.enqueue_summary_post(user:, promo_tag:, original_ids:, tagged_ids_in_original:, injected_ids:, final_ids:, is_skipped_haspromo:, is_skipped_coinflip:, replaced_indices:)
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

        original_topics: pack_topics(original_ids),
        tagged_topics_in_original: pack_topics(tagged_ids_in_original),

        # ONLY the injected promo topics
        injected_topics: pack_topics(injected_ids),

        final_topics: pack_topics(final_ids),

        debug: {
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
