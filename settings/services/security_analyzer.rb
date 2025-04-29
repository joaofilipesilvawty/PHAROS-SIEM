module SIEM
  class SecurityAnalyzer
    def self.analyze_log(log)
      case log.event_type
      when 'login_failed'
        analyze_failed_login(log)
      when 'transaction'
        analyze_transaction(log)
      when 'account_access'
        analyze_account_access(log)
      end

      # Atualizar métricas
      update_metrics(log)
    end

    private

    def self.analyze_failed_login(log)
      # Verificar múltiplas tentativas de login falhas
      failed_attempts = SecurityLog
        .where(user_id: log.user_id)
        .where(event_type: 'login_failed')
        .where(Sequel.lit("timestamp > SYSDATE - #{SIEM.config.alert_thresholds[:multiple_transactions_period]}/86400"))
        .count

      if failed_attempts >= SIEM.config.alert_thresholds[:failed_login_attempts]
        Alert.create_from_security_log(
          log,
          'multiple_failed_logins',
          'high',
          "Multiple failed login attempts for user #{log.user_id}",
          { attempts: failed_attempts }
        )
      end
    end

    def self.analyze_transaction(log)
      details = JSON.parse(log.details)
      amount = details['amount'].to_f

      # Verificar transações suspeitas
      if amount >= SIEM.config.alert_thresholds[:suspicious_transaction_amount]
        Alert.create_from_security_log(
          log,
          'suspicious_transaction',
          'medium',
          "Suspicious transaction amount detected",
          { amount: amount }
        )
      end

      # Verificar múltiplas transações em curto período
      recent_transactions = SecurityLog
        .where(user_id: log.user_id)
        .where(event_type: 'transaction')
        .where(Sequel.lit("timestamp > SYSDATE - #{SIEM.config.alert_thresholds[:multiple_transactions_period]}/86400"))
        .count

      if recent_transactions >= SIEM.config.alert_thresholds[:multiple_transactions_count]
        Alert.create_from_security_log(
          log,
          'unusual_account_activity',
          'medium',
          "Multiple transactions detected in short period",
          { transactions: recent_transactions }
        )
      end
    end

    def self.analyze_account_access(log)
      # Verificar acessos de diferentes IPs
      recent_ips = SecurityLog
        .where(user_id: log.user_id)
        .where(event_type: 'account_access')
        .where(Sequel.lit("timestamp > SYSDATE - #{SIEM.config.alert_thresholds[:multiple_transactions_period]}/86400"))
        .select(:ip_address)
        .distinct
        .count

      if recent_ips > 3 # Limite arbitrário, pode ser ajustado
        Alert.create_from_security_log(
          log,
          'unusual_account_activity',
          'medium',
          "Account accessed from multiple IPs",
          { unique_ips: recent_ips }
        )
      end
    end

    def self.update_metrics(log)
      case log.event_type
      when 'login_failed'
        Metric.record_metric('failed_login_attempts', 1)
      when 'login_success'
        Metric.record_metric('successful_logins', 1)
      when 'transaction'
        details = JSON.parse(log.details)
        Metric.record_metric('total_transactions', 1)
        Metric.record_metric('average_transaction_amount', details['amount'].to_f)
      end
    end
  end
end