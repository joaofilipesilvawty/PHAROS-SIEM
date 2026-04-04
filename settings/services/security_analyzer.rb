module SIEM
  class SecurityAnalyzer
    def self.analyze_log(log)
      return unless log.is_a?(SecurityLog::Record)

      case log.event_type
      when 'login_failed'
        analyze_failed_login(log)
      when 'transaction'
        analyze_transaction(log)
      when 'account_access'
        analyze_account_access(log)
      when 'user_behavior'
        analyze_user_behavior(log)
      end

      update_metrics(log)
    end

    private

    def self.period_start
      secs = SIEM.config.alert_thresholds[:multiple_transactions_period].to_i
      Time.now - secs
    end

    def self.analyze_failed_login(log)
      failed_attempts = SecurityLog.count_in_window(
        user_id: log.user_id,
        event_type: 'login_failed',
        since: period_start
      )

      return unless failed_attempts >= SIEM.config.alert_thresholds[:failed_login_attempts]

      Alert.create_from_security_log(
        log,
        'multiple_failed_logins',
        'high',
        "Multiple failed login attempts for user #{log.user_id}",
        { attempts: failed_attempts }
      )
    end

    def self.analyze_transaction(log)
      details = JSON.parse(log.details.to_s)
      amount = details['amount'].to_f

      if amount >= SIEM.config.alert_thresholds[:suspicious_transaction_amount]
        Alert.create_from_security_log(
          log,
          'suspicious_transaction',
          'medium',
          'Suspicious transaction amount detected',
          { amount: amount }
        )
      end

      recent_transactions = SecurityLog.count_in_window(
        user_id: log.user_id,
        event_type: 'transaction',
        since: period_start
      )

      return unless recent_transactions >= SIEM.config.alert_thresholds[:multiple_transactions_count]

      Alert.create_from_security_log(
        log,
        'unusual_account_activity',
        'medium',
        'Multiple transactions detected in short period',
        { transactions: recent_transactions }
      )
    end

    def self.analyze_account_access(log)
      recent_ips = SecurityLog.distinct_ip_count(
        user_id: log.user_id,
        event_type: 'account_access',
        since: period_start
      )

      if recent_ips > 3
        Alert.create_from_security_log(
          log,
          'unusual_account_activity',
          'medium',
          'Account accessed from multiple IPs',
          { unique_ips: recent_ips }
        )
      end

      detect_access_time_anomaly(log)
    end

    def self.detect_access_time_anomaly(log)
      since = Time.now - (30 * 86_400)
      access_times = SecurityLog.timestamps_for(
        user_id: log.user_id,
        event_type: 'account_access',
        since: since
      ).map(&:hour)

      current_hour = log.timestamp.hour

      if access_times.any? && (current_hour < access_times.min - 3 || current_hour > access_times.max + 3)
        Alert.create_from_security_log(
          log,
          'anomalous_access_time',
          'medium',
          'Account accessed at unusual time',
          { current_hour: current_hour, typical_range: [access_times.min, access_times.max] }
        )
      end
    end

    def self.analyze_user_behavior(log)
      details = JSON.parse(log.details.to_s)
      action = details['action']

      since = Time.now - (7 * 86_400)
      user_actions = SecurityLog.behavior_actions(user_id: log.user_id, since: since)

      if user_actions.any? && action && !user_actions.include?(action)
        Alert.create_from_security_log(
          log,
          'unusual_user_behavior',
          'low',
          'Unusual user behavior detected',
          { action: action, typical_actions: user_actions.uniq }
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
        details = JSON.parse(log.details.to_s)
        Metric.record_metric('total_transactions', 1)
        Metric.record_metric('average_transaction_amount', details['amount'].to_f)
      end
    end
  end
end
