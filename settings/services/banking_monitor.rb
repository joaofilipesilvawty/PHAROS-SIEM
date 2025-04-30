module SIEM
  class BankingMonitor
    def self.analyze_transaction(transaction)
      # Verificar transações suspeitas
      check_suspicious_amount(transaction)
      check_multiple_transactions(transaction)
      check_unusual_patterns(transaction)
      check_compliance(transaction)
    end

    private

    def self.check_suspicious_amount(transaction)
      return unless transaction[:amount].to_f >= SIEM.config.alert_thresholds[:suspicious_transaction_amount]

      Alert.create(
        alert_type: 'suspicious_transaction',
        severity: 'high',
        message: "Transação suspeita detectada: #{transaction[:amount]}",
        details: {
          transaction_id: transaction[:id],
          amount: transaction[:amount],
          vat_number: transaction[:vat_number],
          timestamp: transaction[:timestamp]
        }
      )
    end

    def self.check_multiple_transactions(transaction)
      recent_transactions = DB[:transactions]
        .where(vat_number: transaction[:vat_number])
        .where(Sequel.lit("timestamp > SYSDATE - #{SIEM.config.alert_thresholds[:multiple_transactions_period]}/86400"))
        .count

      if recent_transactions >= SIEM.config.alert_thresholds[:multiple_transactions_count]
        Alert.create(
          alert_type: 'unusual_activity',
          severity: 'medium',
          message: "Múltiplas transações em curto período",
          details: {
            vat_number: transaction[:vat_number],
            transaction_count: recent_transactions,
            period: SIEM.config.alert_thresholds[:multiple_transactions_period]
          }
        )
      end
    end

    def self.check_unusual_patterns(transaction)
      # Verificar padrões incomuns de transações
      check_velocity(transaction)
      check_geolocation(transaction)
      check_device_fingerprint(transaction)
    end

    def self.check_velocity(transaction)
      # Verificar velocidade de transações
      last_hour_transactions = DB[:transactions]
        .where(vat_number: transaction[:vat_number])
        .where(Sequel.lit("timestamp > SYSDATE - 1/24"))
        .count

      if last_hour_transactions > 10 # Limite arbitrário, ajuste conforme necessário
        Alert.create(
          alert_type: 'high_velocity',
          severity: 'medium',
          message: "Alta velocidade de transações detectada",
          details: {
            vat_number: transaction[:vat_number],
            transaction_count: last_hour_transactions,
            period: '1 hora'
          }
        )
      end
    end

    def self.check_geolocation(transaction)
      # Verificar localização da transação
      last_location = DB[:transactions]
        .where(vat_number: transaction[:vat_number])
        .where(Sequel.lit("timestamp > SYSDATE - 1"))
        .order(Sequel.desc(:timestamp))
        .first

      return unless last_location && transaction[:ip_address]

      if last_location[:ip_address] != transaction[:ip_address]
        # Verificar se a distância entre as localizações é suspeita
        Alert.create(
          alert_type: 'suspicious_location',
          severity: 'medium',
          message: "Mudança suspeita de localização detectada",
          details: {
            vat_number: transaction[:vat_number],
            previous_ip: last_location[:ip_address],
            current_ip: transaction[:ip_address],
            timestamp: transaction[:timestamp]
          }
        )
      end
    end

    def self.check_device_fingerprint(transaction)
      # Verificar impressão digital do dispositivo
      return unless transaction[:device_fingerprint]

      unusual_devices = DB[:transactions]
        .where(vat_number: transaction[:vat_number])
        .where(Sequel.lit("timestamp > SYSDATE - 7"))
        .select(:device_fingerprint)
        .distinct
        .count

      if unusual_devices > 3
        Alert.create(
          alert_type: 'multiple_devices',
          severity: 'medium',
          message: "Múltiplos dispositivos detectados",
          details: {
            vat_number: transaction[:vat_number],
            device_count: unusual_devices,
            period: '7 dias'
          }
        )
      end
    end

    def self.check_compliance(transaction)
      # Verificar conformidade com regulamentações
      check_aml(transaction)
      check_kyc(transaction)
      check_sanctions(transaction)
    end

    def self.check_aml(transaction)
      # Verificar Anti-Money Laundering
      return unless transaction[:amount].to_f >= 10000 # Limite para relatórios AML

      Alert.create(
        alert_type: 'aml_threshold',
        severity: 'high',
        message: "Transação acima do limite AML",
        details: {
          transaction_id: transaction[:id],
          amount: transaction[:amount],
          vat_number: transaction[:vat_number],
          timestamp: transaction[:timestamp]
        }
      )
    end

    def self.check_kyc(transaction)
      # Verificar Know Your Customer
      user = DB[:users].where(vat_number: transaction[:vat_number]).first
      return unless user

      if user[:kyc_status] != 'verified'
        Alert.create(
          alert_type: 'kyc_warning',
          severity: 'high',
          message: "Transação com usuário não verificado",
          details: {
            transaction_id: transaction[:id],
            vat_number: transaction[:vat_number],
            kyc_status: user[:kyc_status]
          }
        )
      end
    end

    def self.check_sanctions(transaction)
      # Verificar listas de sanções
      # Implemente a lógica de verificação de sanções aqui
    end
  end
end