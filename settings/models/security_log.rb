module SIEM
  class SecurityLog
    DS = DB[:security_logs]

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

      id = DS.insert(
        event_type: h[:event_type].to_s,
        source: h[:source].to_s,
        severity: h[:severity].to_s,
        message: h[:message].to_s,
        timestamp: ts,
        user_id: h[:user_id].to_s,
        ip_address: h[:ip_address].to_s,
        details: details_str
      )
      id ||= DS.max(:id)

      Record.new(
        id: id,
        event_type: h[:event_type].to_s,
        source: h[:source].to_s,
        severity: h[:severity].to_s,
        message: h[:message].to_s,
        timestamp: ts,
        user_id: h[:user_id].to_s,
        ip_address: h[:ip_address].to_s,
        details: details_str
      )
    end

    def self.parse_ts(raw)
      return Time.now if raw.nil?
      return raw if raw.is_a?(Time)
      Time.parse(raw.to_s)
    rescue ArgumentError
      Time.now
    end

    def self.row_to_hash(row)
      r = row.is_a?(Hash) ? row : row.to_hash
      {
        id: r[:id],
        event_type: r[:event_type],
        source: r[:source],
        severity: r[:severity],
        message: r[:message],
        timestamp: parse_ts(r[:timestamp]),
        user_id: r[:user_id],
        ip_address: r[:ip_address],
        details: r[:details]
      }
    end

    def self.recent(limit: 100)
      DS.reverse(:timestamp).limit(limit).map { |row| row_to_hash(row) }
    end

    def self.for_user(user_id, limit: 100)
      DS.where(user_id: user_id.to_s).reverse(:timestamp).limit(limit).map { |row| row_to_hash(row) }
    end

    def self.count_in_window(user_id:, event_type:, since:)
      return 0 if user_id.nil? || user_id.to_s.empty?

      DS.where(user_id: user_id.to_s, event_type: event_type.to_s).where { timestamp >= since }.count
    end

    def self.distinct_ip_count(user_id:, event_type:, since:)
      return 0 if user_id.nil? || user_id.to_s.empty?

      ips = DS.where(user_id: user_id.to_s, event_type: event_type.to_s)
              .where { timestamp >= since }
              .select_map(:ip_address)
      ips.compact.uniq.size
    end

    def self.timestamps_for(user_id:, event_type:, since:)
      return [] if user_id.nil? || user_id.to_s.empty?

      DS.where(user_id: user_id.to_s, event_type: event_type.to_s)
        .where { timestamp >= since }
        .reverse(:timestamp)
        .limit(500)
        .select_map(:timestamp)
        .map { |t| parse_ts(t) }
    end

    def self.behavior_actions(user_id:, since:)
      return [] if user_id.nil? || user_id.to_s.empty?

      DS.where(user_id: user_id.to_s, event_type: 'user_behavior')
        .where { timestamp >= since }
        .reverse(:timestamp)
        .limit(200)
        .select_map(:details)
        .filter_map do |raw|
          next if raw.nil? || raw.to_s.empty?
          parsed = raw.is_a?(Hash) ? raw : JSON.parse(raw.to_s)
          parsed['action'] || parsed[:action]
        rescue JSON::ParserError
          nil
        end
    end

    def self.hourly_activity_last_hours(hours)
      since = Time.now - (hours * 3600)
      rows = DS.where { timestamp >= since }.order(:timestamp).limit(10_000).select_map(:timestamp)

      buckets = Hash.new(0)
      rows.each do |t|
        tt = parse_ts(t)
        key = tt.strftime('%Y-%m-%d %H:00:00')
        buckets[key] += 1
      end

      labels = buckets.keys.sort
      { labels: labels, data: labels.map { |k| buckets[k] } }
    end
  end
end
