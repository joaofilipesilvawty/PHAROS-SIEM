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

      admin = DB[:admins].where(username: username).first
      return { success: false, message: 'Invalid username or password' } unless admin

      stored_hash = BCrypt::Password.new(admin[:password_hash])
      unless stored_hash == password
        return { success: false, message: 'Invalid username or password' }
      end

      { success: true, admin_id: admin[:id] }
    end

    def self.logout(request)
      request.session.clear
      { success: true, message: 'Logout successful' }
    end

    def self.current_user(request)
      return nil unless request.session[:admin_id]
      SIEM::Admin.find_by_id(request.session[:admin_id])
    end

    def self.admin_login(request)
      data = JSON.parse(request.body.read)
      username = data['username']
      password = data['password']

      admin = DB[:admins].where(username: username).first
      return { status: 401, body: { error: 'Invalid username or password' }.to_json } unless admin

      stored_hash = BCrypt::Password.new(admin[:password_hash])
      unless stored_hash == password
        return { status: 401, body: { error: 'Invalid username or password' }.to_json }
      end

      session_id = SecureRandom.uuid
      DB[:sessions].insert(
        id: session_id,
        admin_id: admin[:id],
        created_at: Time.now,
        expires_at: Time.now + (24 * 60 * 60) # 24 hours
      )

      {
        status: 200,
        body: {
          message: 'Login successful',
          session_id: session_id,
          admin: {
            id: admin[:id],
            username: admin[:username],
            created_at: admin[:created_at],
            updated_at: admin[:updated_at]
          }
        }.to_json
      }
    end

    def self.admin_logout(request)
      session_id = request.env['HTTP_AUTHORIZATION']&.split(' ')&.last

      if session_id
        DB[:sessions].where(id: session_id).delete
        {
          status: 200,
          body: {
            message: 'Logged out successfully'
          }.to_json
        }
      else
        {
          status: 401,
          body: {
            error: 'No session provided'
          }.to_json
        }
      end
    end

    def self.verify_session(session_id)
      session = DB[:sessions].where(id: session_id)
        .where(Sequel.lit('expires_at > ?', Time.now))
        .first

      return nil unless session

      admin = DB[:admins][id: session[:admin_id]]
      return nil unless admin

      Admin.new(id: admin[:id], username: admin[:username])
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