module SIEM
  class Alert
    INDEX = 'alerts'.freeze

    ALERT_TYPES = %w[
      multiple_failed_logins
      suspicious_transaction
      unusual_account_activity
      potential_fraud
      system_anomaly
      security_breach
      anomalous_access_time
      unusual_user_behavior
      threat_detection
    ].freeze

    SEVERITIES = %w[low medium high critical].freeze

    STATUSES = %w[new in_progress resolved ignored].freeze

    Instance = Struct.new(
      :id, :alert_type, :severity, :message, :timestamp, :status, :details_raw,
      keyword_init: true
    ) do
      def details
        JSON.parse(details_raw.to_s)
      rescue JSON::ParserError
        {}
      end

      def to_hash
        {
          id: id,
          alert_type: alert_type,
          severity: severity,
          message: message,
          timestamp: normalize_time(timestamp),
          status: status,
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

    def self.validate_alert(alert_data)
      h = alert_data.transform_keys { |k| k.to_sym }
      return false unless ALERT_TYPES.include?(h[:alert_type].to_s)
      return false unless SEVERITIES.include?(h[:severity].to_s)
      return false unless STATUSES.include?(h[:status].to_s)
      return false if h[:alert_type].nil? || h[:severity].nil? ||
                     h[:message].nil? || h[:timestamp].nil? ||
                     h[:status].nil?
      true
    end

    def self.create_from_security_log(_log, alert_type, severity, message, details = {})
      details_json = details.to_json
      ts = Time.now
      body = {
        alert_type: alert_type.to_s,
        severity: severity.to_s,
        message: message.to_s,
        timestamp: ts.iso8601,
        status: 'new',
        details: details_json
      }

      response = ES.index(index: INDEX, body: body)

      inst = Instance.new(
        id: response['_id'],
        alert_type: body[:alert_type],
        severity: body[:severity],
        message: body[:message],
        timestamp: ts,
        status: 'new',
        details_raw: details_json
      )
      ResponseAutomation.execute_response(inst)
      inst
    end

    def self.from_hit(hit)
      s = hit['_source'] || {}
      Instance.new(
        id: hit['_id'],
        alert_type: s['alert_type'],
        severity: s['severity'],
        message: s['message'],
        timestamp: parse_ts(s['timestamp']),
        status: s['status'],
        details_raw: s['details']
      )
    end

    def self.parse_ts(raw)
      return Time.now if raw.nil?
      return raw if raw.is_a?(Time)
      Time.parse(raw.to_s)
    rescue ArgumentError
      Time.now
    end

    def self.find_by_id(id)
      doc = ES.get(index: INDEX, id: id.to_s)
      return nil unless doc && doc['found']
      from_hit({ '_id' => doc['_id'], '_source' => doc['_source'] })
    rescue StandardError
      nil
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
      (res['hits']['hits'] || []).map { |h| from_hit(h) }
    end

    def self.count_by_severity(severity)
      ES.count(
        index: INDEX,
        body: {
          query: { term: { severity: severity.to_s } }
        }
      )['count'].to_i
    end

    def self.update_status(id, status)
      ES.update(
        index: INDEX,
        id: id.to_s,
        body: { doc: { status: status.to_s } }
      )
    end
  end
end
