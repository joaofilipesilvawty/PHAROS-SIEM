module SIEM
  class Alert < Sequel::Model(OS[:alerts])
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

    def self.validate_alert(alert_data)
      return false unless ALERT_TYPES.include?(alert_data[:alert_type])
      return false unless SEVERITIES.include?(alert_data[:severity])
      return false unless STATUSES.include?(alert_data[:status])
      return false if alert_data[:alert_type].nil? || alert_data[:severity].nil? ||
                     alert_data[:message].nil? || alert_data[:timestamp].nil? ||
                     alert_data[:status].nil?
      true
    end

    def self.create_from_security_log(log, alert_type, severity, message, details = {})
      alert = create(
        alert_type: alert_type,
        severity: severity,
        message: message,
        timestamp: Time.now,
        status: 'open',
        details: details.to_json
      )
      # Trigger automated response
      ResponseAutomation.execute_response(alert)
      alert
    end

    def self.where(conditions = {})
      query = {
        bool: {
          must: conditions.map do |field, value|
            { term: { field => value } }
          end
        }
      }

      response = ES.search(
        index: 'alerts',
        body: {
          query: query
        }
      )

      response['hits']['hits'].map do |hit|
        hit['_source'].merge(id: hit['_id'])
      end
    end

    def self.order(field, direction = :desc)
      response = ES.search(
        index: 'alerts',
        body: {
          sort: [
            { field => { order: direction.to_s } }
          ]
        }
      )

      response['hits']['hits'].map do |hit|
        hit['_source'].merge(id: hit['_id'])
      end
    end
  end
end