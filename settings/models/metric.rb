module SIEM
  class Metric < Sequel::Model(:metrics)
    plugin :json_serializer
    plugin :timestamps, update_on_create: true

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
    ].freeze

    def validate
      super
      validates_includes METRIC_TYPES, :metric_type, message: "must be one of: #{METRIC_TYPES.join(', ')}"
      validates_presence [:metric_type, :value, :timestamp, :source]
    end

    def self.record_metric(metric_type, value, source = 'system')
      create(
        metric_type: metric_type,
        value: value,
        timestamp: Time.now,
        source: source
      )
    end

    def self.get_latest_metrics(metric_type, limit = 100)
      where(metric_type: metric_type)
        .order(Sequel.desc(:timestamp))
        .limit(limit)
        .all
    end
  end
end