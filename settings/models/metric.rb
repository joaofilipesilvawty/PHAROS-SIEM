module OPSMON
  class Metric
    DS = DB[:metrics]

    METRIC_TYPES = %w[
      failed_login_attempts
      successful_logins
      suspicious_transactions
      total_transactions
      average_transaction_amount
      system_errors
      api_requests
      response_time
      cpu_usage
      memory_usage
      disk_usage
      network_traffic
      api_latency
      error_rate
    ].freeze

    def self.validate_metric(metric_data)
      return false unless METRIC_TYPES.include?(metric_data[:metric_type].to_s)
      return false if metric_data[:metric_type].nil? || metric_data[:value].nil? ||
                     metric_data[:timestamp].nil?
      true
    end

    def self.record_metric(metric_type, value, source = 'system')
      metric_data = {
        metric_type: metric_type.to_s,
        value: value.to_f,
        timestamp: Time.now,
        source: source.to_s
      }

      return nil unless validate_metric(metric_data)

      id = DS.insert(metric_data)
      id ||= DS.max(:id)
      OPSMON::RuntimeMetrics.inc_opsmon_metric_insert('default', metric_type.to_s)
      id
    end

    def self.get_latest_metrics(metric_type, limit = 100)
      DS.where(metric_type: metric_type.to_s)
        .reverse(:timestamp)
        .limit(limit)
        .map do |r|
          h = r.is_a?(Hash) ? r : r.to_hash
          {
            'id' => h[:id],
            'metric_type' => h[:metric_type],
            'value' => h[:value],
            'timestamp' => h[:timestamp],
            'source' => h[:source]
          }
        end
    end
  end
end
