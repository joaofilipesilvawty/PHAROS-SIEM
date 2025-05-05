module SIEM
  class SecurityLog
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

    def self.validate_log(log_data)
      return false unless EVENT_TYPES.include?(log_data[:event_type])
      return false unless SEVERITIES.include?(log_data[:severity])
      return false if log_data[:event_type].nil? || log_data[:source].nil? ||
                     log_data[:severity].nil? || log_data[:message].nil? ||
                     log_data[:timestamp].nil?
      true
    end

    def self.create_from_python_log(log_data)
      return nil unless validate_log(log_data)

      response = ES.index(
        index: 'security_logs',
        body: {
          event_type: log_data['event_type'],
          source: 'python_fintech',
          severity: log_data['severity'],
          message: log_data['message'],
          timestamp: Time.parse(log_data['timestamp']),
          user_id: log_data['user_id'],
          ip_address: log_data['ip_address'],
          details: log_data['details'].to_json
        }
      )

      response['_id']
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
        index: 'security_logs',
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
        index: 'security_logs',
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