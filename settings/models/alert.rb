module OPSMON
  class Alert
    DS = DB[:alerts]

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
        raw = details_raw
        return raw if raw.is_a?(Hash)
        JSON.parse(raw.to_s)
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
      details_json = details.is_a?(String) ? details : details.to_json
      ts = Time.now

      id = DS.insert(
        alert_type: alert_type.to_s,
        severity: severity.to_s,
        message: message.to_s,
        timestamp: ts,
        status: 'new',
        details: details_json
      )
      id ||= DS.max(:id)

      inst = Instance.new(
        id: id,
        alert_type: alert_type.to_s,
        severity: severity.to_s,
        message: message.to_s,
        timestamp: ts,
        status: 'new',
        details_raw: details_json
      )
      ResponseAutomation.execute_response(inst)
      inst
    end

    def self.parse_ts(raw)
      return Time.now if raw.nil?
      return raw if raw.is_a?(Time)
      Time.parse(raw.to_s)
    rescue ArgumentError
      Time.now
    end

    def self.normalize_details(raw)
      return raw.to_json if raw.is_a?(Hash)
      raw.to_s
    end

    def self.from_row(row)
      return nil unless row
      r = row.is_a?(Hash) ? row : row.to_hash
      Instance.new(
        id: r[:id],
        alert_type: r[:alert_type],
        severity: r[:severity],
        message: r[:message],
        timestamp: parse_ts(r[:timestamp]),
        status: r[:status],
        details_raw: r[:details]
      )
    end

    def self.find_by_id(id)
      row = DS[id: id.to_i]
      from_row(row)
    end

    def self.recent(limit: 100)
      DS.reverse(:timestamp).limit(limit).map { |row| from_row(row) }
    end

    def self.count_by_severity(severity)
      DS.where(severity: severity.to_s).count
    end

    def self.update_status(id, status)
      new_status = status.to_s
      updated = DS.where(id: id.to_i).update(status: new_status)
      if updated.to_i.positive? && %w[in_progress resolved ignored].include?(new_status)
        OPSMON::RuntimeMetrics.inc_opsmon_alert_acked('default')
      end
      updated
    end
  end
end
