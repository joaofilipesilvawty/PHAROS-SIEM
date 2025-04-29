module SIEM
  class SecurityLog < Sequel::Model(:security_logs)
    plugin :json_serializer
    plugin :timestamps, update_on_create: true

    # Tipos de eventos suportados
    EVENT_TYPES = %w[
      login_success
      login_failed
      transaction
      account_access
      password_change
      suspicious_activity
      system_error
    ].freeze

    # Níveis de severidade
    SEVERITIES = %w[low medium high critical].freeze

    def validate
      super
      validates_includes EVENT_TYPES, :event_type, message: "must be one of: #{EVENT_TYPES.join(', ')}"
      validates_includes SEVERITIES, :severity, message: "must be one of: #{SEVERITIES.join(', ')}"
      validates_presence [:event_type, :source, :severity, :message, :timestamp]
    end

    def self.create_from_python_log(log_data)
      create(
        event_type: log_data['event_type'],
        source: 'python_fintech',
        severity: log_data['severity'],
        message: log_data['message'],
        timestamp: Time.parse(log_data['timestamp']),
        user_id: log_data['user_id'],
        ip_address: log_data['ip_address'],
        details: log_data['details'].to_json
      )
    end
  end
end