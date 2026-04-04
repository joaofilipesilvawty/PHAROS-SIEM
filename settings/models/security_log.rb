module SIEM
  class SecurityLog
    INDEX = 'security_logs'.freeze

    EVENT_TYPES = %w[
      login_success
      login_failed
      transaction
      account_access
      password_change
      suspicious_activity
      system_error
      user_behavior
    ].freeze

    SEVERITIES = %w[low medium high critical].freeze

    Record = Struct.new(
      :id, :event_type, :source, :severity, :message, :timestamp,
      :user_id, :ip_address, :details,
      keyword_init: true
    ) do
      def to_hash
        {
          id: id,
          event_type: event_type,
          source: source,
          severity: severity,
          message: message,
          timestamp: normalize_time(timestamp),
          user_id: user_id,
          ip_address: ip_address,
          details: details
        }
      end

      def normalize_time(ts)
        return Time.now if ts.nil?
        return ts if ts.is_a?(Time)
        Time.parse(ts.to_s)
      rescue ArgumentError
        Time.now
      end
    end

    def self.symbolize_log_data(log_data)
      return {} unless log_data.is_a?(Hash)
      log_data.transform_keys { |k| k.to_sym }
    end

    def self.validate_log(log_data)
      h = symbolize_log_data(log_data)
      return false unless EVENT_TYPES.include?(h[:event_type].to_s)
      return false unless SEVERITIES.include?(h[:severity].to_s)
      return false if h[:event_type].nil? || h[:source].nil? ||
                     h[:severity].nil? || h[:message].nil? ||
                     h[:timestamp].nil?
      true
    end

    def self.create_from_python_log(log_data)
      h = symbolize_log_data(log_data)
      h[:source] ||= 'python_fintech'
      return nil unless validate_log(h)

      details_val = h[:details]
      details_str =
        case details_val
        when String then details_val
        when nil then '{}'
        else details_val.to_json
        end

      ts = h[:timestamp].is_a?(Time) ? h[:timestamp] : Time.parse(h[:timestamp].to_s)

      body = {
        event_type: h[:event_type].to_s,
        source: h[:source].to_s,
        severity: h[:severity].to_s,
        message: h[:message].to_s,
        timestamp: ts.iso8601,
        user_id: h[:user_id].to_s,
        ip_address: h[:ip_address].to_s,
        details: details_str
      }

      response = ES.index(index: INDEX, body: body)

      Record.new(
        id: response['_id'],
        event_type: body[:event_type],
        source: body[:source],
        severity: body[:severity],
        message: body[:message],
        timestamp: ts,
        user_id: body[:user_id],
        ip_address: body[:ip_address],
        details: details_str
      )
    end

    def self.from_hit(hit)
      s = hit['_source'] || {}
      Record.new(
        id: hit['_id'],
        event_type: s['event_type'],
        source: s['source'],
        severity: s['severity'],
        message: s['message'],
        timestamp: parse_ts(s['timestamp']),
        user_id: s['user_id'],
        ip_address: s['ip_address'],
        details: s['details']
      )
    end

    def self.parse_ts(raw)
      return Time.now if raw.nil?
      return raw if raw.is_a?(Time)
      Time.parse(raw.to_s)
    rescue ArgumentError
      Time.now
    end

    def self.recent(limit: 100)
      res = ES.search(
        index: INDEX,
        body: {
          query: { match_all: {} },
          sort: [{ timestamp: { order: 'desc' } }],
          size: limit
        }
      )
      (res['hits']['hits'] || []).map { |h| from_hit(h).to_hash }
    end

    def self.for_user(user_id, limit: 100)
      res = ES.search(
        index: INDEX,
        body: {
          query: { term: { user_id: user_id.to_s } },
          sort: [{ timestamp: { order: 'desc' } }],
          size: limit
        }
      )
      (res['hits']['hits'] || []).map { |h| from_hit(h).to_hash }
    end

    def self.count_in_window(user_id:, event_type:, since:)
      return 0 if user_id.nil? || user_id.to_s.empty?

      ES.count(
        index: INDEX,
        body: {
          query: {
            bool: {
              must: [
                { term: { user_id: user_id.to_s } },
                { term: { event_type: event_type.to_s } },
                { range: { timestamp: { gte: since.iso8601 } } }
              ]
            }
          }
        }
      )['count'].to_i
    end

    def self.distinct_ip_count(user_id:, event_type:, since:)
      return 0 if user_id.nil? || user_id.to_s.empty?

      res = ES.search(
        index: INDEX,
        body: {
          size: 0,
          query: {
            bool: {
              must: [
                { term: { user_id: user_id.to_s } },
                { term: { event_type: event_type.to_s } },
                { range: { timestamp: { gte: since.iso8601 } } }
              ]
            }
          },
          aggs: {
            unique_ips: { cardinality: { field: 'ip_address' } }
          }
        }
      )
      (res.dig('aggregations', 'unique_ips', 'value') || 0).to_i
    end

    def self.timestamps_for(user_id:, event_type:, since:)
      return [] if user_id.nil? || user_id.to_s.empty?

      res = ES.search(
        index: INDEX,
        body: {
          query: {
            bool: {
              must: [
                { term: { user_id: user_id.to_s } },
                { term: { event_type: event_type.to_s } },
                { range: { timestamp: { gte: since.iso8601 } } }
              ]
            }
          },
          sort: [{ timestamp: { order: 'desc' } }],
          size: 500,
          _source: ['timestamp']
        }
      )
      (res['hits']['hits'] || []).map do |hit|
        parse_ts(hit.dig('_source', 'timestamp'))
      end
    end

    def self.behavior_actions(user_id:, since:)
      return [] if user_id.nil? || user_id.to_s.empty?

      res = ES.search(
        index: INDEX,
        body: {
          query: {
            bool: {
              must: [
                { term: { user_id: user_id.to_s } },
                { term: { event_type: 'user_behavior' } },
                { range: { timestamp: { gte: since.iso8601 } } }
              ]
            }
          },
          sort: [{ timestamp: { order: 'desc' } }],
          size: 200,
          _source: ['details']
        }
      )
      (res['hits']['hits'] || []).filter_map do |hit|
        raw = hit.dig('_source', 'details')
        next if raw.nil? || raw.to_s.empty?
        parsed = JSON.parse(raw.to_s)
        parsed['action']
      rescue JSON::ParserError
        nil
      end
    end

    def self.hourly_activity_last_hours(hours)
      since = Time.now - (hours * 3600)
      res = ES.search(
        index: INDEX,
        body: {
          query: { range: { timestamp: { gte: since.iso8601 } } },
          sort: [{ timestamp: { order: 'asc' } }],
          size: 10_000,
          _source: ['timestamp']
        }
      )

      buckets = Hash.new(0)
      (res['hits']['hits'] || []).each do |hit|
        t = parse_ts(hit.dig('_source', 'timestamp'))
        key = t.strftime('%Y-%m-%d %H:00:00')
        buckets[key] += 1
      end

      labels = buckets.keys.sort
      { labels: labels, data: labels.map { |k| buckets[k] } }
    end
  end
end
