# =============================================
# Endpoints Module
# =============================================
module SIEM
  module Endpoints
    # =============================================
    # Health Check Endpoint
    # =============================================
    def self.health_check
      begin
        DB.test_connection
        json status: 'healthy', database: 'connected'
      rescue => e
        json status: 'unhealthy', error: e.message
      end
    end

    # =============================================
    # Logs Endpoints
    # =============================================
    def self.create_log(request)
      request.body.rewind
      log_data = JSON.parse(request.body.read)

      log = SecurityLog.create_from_python_log(log_data)
      SecurityAnalyzer.analyze_log(log)

      json status: 'received', log_id: log.id
    end

    def self.get_logs
      logs = SecurityLog.order(Sequel.desc(:timestamp)).limit(100).all
      json logs: logs.map(&:to_hash)
    end

    def self.get_user_logs(user_id)
      logs = SecurityLog
        .where(user_id: user_id)
        .order(Sequel.desc(:timestamp))
        .limit(100)
        .all
      json logs: logs.map(&:to_hash)
    end

    # =============================================
    # Alerts Endpoints
    # =============================================
    def self.get_alerts
      alerts = Alert.order(Sequel.desc(:timestamp)).limit(100).all
      json alerts: alerts.map(&:to_hash)
    end

    def self.update_alert(alert_id, request)
      alert = Alert[alert_id]
      return json error: 'Alert not found', status: 404 unless alert

      request.body.rewind
      update_data = JSON.parse(request.body.read)

      if update_data['status'] && Alert::STATUSES.include?(update_data['status'])
        alert.update(status: update_data['status'])
        json alert: alert.to_hash
      else
        json error: 'Invalid status', status: 400
      end
    end

    # =============================================
    # Metrics Endpoint
    # =============================================
    def self.get_metrics
      metrics = {}
      Metric::METRIC_TYPES.each do |metric_type|
        metrics[metric_type] = Metric.get_latest_metrics(metric_type)
      end
      json metrics: metrics
    end
  end
end