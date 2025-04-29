module SIEM
  class Alert < Sequel::Model(:alerts)
    plugin :json_serializer
    plugin :timestamps, update_on_create: true

    # Tipos de alertas
    ALERT_TYPES = %w[
      multiple_failed_logins
      suspicious_transaction
      unusual_account_activity
      potential_fraud
      system_anomaly
      security_breach
    ].freeze

    # Níveis de severidade
    SEVERITIES = %w[low medium high critical].freeze

    # Status possíveis
    STATUSES = %w[new in_progress resolved ignored].freeze

    def validate
      super
      validates_includes ALERT_TYPES, :alert_type, message: "must be one of: #{ALERT_TYPES.join(', ')}"
      validates_includes SEVERITIES, :severity, message: "must be one of: #{SEVERITIES.join(', ')}"
      validates_includes STATUSES, :status, message: "must be one of: #{STATUSES.join(', ')}"
      validates_presence [:alert_type, :severity, :message, :timestamp, :status]
    end

    def self.create_from_security_log(log, alert_type, severity, message, details = {})
      create(
        alert_type: alert_type,
        severity: severity,
        message: message,
        timestamp: Time.now,
        status: 'new',
        details: {
          log_id: log.id,
          user_id: log.user_id,
          ip_address: log.ip_address,
          **details
        }.to_json
      )
    end
  end
end