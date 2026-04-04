module SIEM
  class Metric
    # Tipos de métricas
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
      return false unless METRIC_TYPES.include?(metric_data[:metric_type])
      return false if metric_data[:metric_type].nil? || metric_data[:value].nil? ||
                     metric_data[:timestamp].nil? || metric_data[:source].nil?
      true
    end

    def self.record_metric(metric_type, value, source = 'system')
      metric_data = {
        metric_type: metric_type,
        value: value,
        timestamp: Time.now,
        source: source
      }

      return nil unless validate_metric(metric_data)

      response = ES.index(
        index: 'metrics',
        body: metric_data
      )

      response['_id']
    end

    def self.get_latest_metrics(metric_type, limit = 100)
      response = ES.search(
        index: 'metrics',
        body: {
          query: {
            term: { metric_type: metric_type }
          },
          sort: [
            { timestamp: { order: 'desc' } }
          ],
          size: limit
        }
      )

      response['hits']['hits'].map do |hit|
        hit['_source'].merge(id: hit['_id'])
      end
    end
  end
end