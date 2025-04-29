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
        { status: 'healthy', database: 'connected' }
      rescue => e
        { status: 'unhealthy', error: e.message }
      end
    end

    # =============================================
    # Authentication Endpoints
    # =============================================
    def self.login(request)
      username = request.params['username']
      password = request.params['password']

      admin = SIEM::Admin.authenticate(username, password)
      if admin
        request.session[:admin_id] = admin.id
        { success: true, message: 'Login successful' }
      else
        { success: false, message: 'Invalid credentials' }
      end
    end

    def self.logout(request)
      request.session.clear
      { success: true, message: 'Logout successful' }
    end

    def self.current_user(request)
      return nil unless request.session[:admin_id]
      SIEM::Admin.find_by_id(request.session[:admin_id])
    end

    # =============================================
    # Logs Endpoints
    # =============================================
    def self.create_log(request)
      request.body.rewind
      log_data = JSON.parse(request.body.read)

      log = SecurityLog.create_from_python_log(log_data)
      SecurityAnalyzer.analyze_log(log)

      { status: 'received', log_id: log.id }
    end

    def self.get_logs
      logs = SecurityLog.order(Sequel.desc(:timestamp)).limit(100).all
      { logs: logs.map(&:to_hash) }
    end

    def self.get_user_logs(user_id)
      logs = SecurityLog
        .where(user_id: user_id)
        .order(Sequel.desc(:timestamp))
        .limit(100)
        .all
      { logs: logs.map(&:to_hash) }
    end

    # =============================================
    # Alerts Endpoints
    # =============================================
    def self.get_alerts
      alerts = Alert.order(Sequel.desc(:timestamp)).limit(100).all
      { alerts: alerts.map(&:to_hash) }
    end

    def self.update_alert(alert_id, request)
      alert = Alert[alert_id]
      return { error: 'Alert not found', status: 404 } unless alert

      request.body.rewind
      update_data = JSON.parse(request.body.read)

      if update_data['status'] && Alert::STATUSES.include?(update_data['status'])
        alert.update(status: update_data['status'])
        { alert: alert.to_hash }
      else
        { error: 'Invalid status', status: 400 }
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
      { metrics: metrics }
    end
  end
end