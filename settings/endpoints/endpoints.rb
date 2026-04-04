# =============================================
# Endpoints Module
# =============================================
require 'securerandom'

module SIEM
  module Endpoints
    def self.health_check
      SIEM::Database.test_connection(DB)
      { status: 'healthy', database: 'oracle' }
    rescue StandardError => e
      { status: 'unhealthy', error: e.message }
    end

    def self.login(request)
      username = request.params['username']
      password = request.params['password']

      admin = Admin.authenticate(username, password)
      return { success: false, message: 'Invalid username or password' } unless admin

      { success: true, admin_id: admin.id }
    end

    def self.logout(request)
      request.session.clear
      { success: true, message: 'Logout successful' }
    end

    def self.current_user(request)
      return nil unless request.session[:admin_id]

      Admin.find_by_id(request.session[:admin_id])
    end

    def self.admin_login(request)
      data = JSON.parse(request.body.read)
      username = data['username']
      password = data['password']

      admin = Admin.authenticate(username, password)
      return { status: 401, body: { error: 'Invalid username or password' }.to_json } unless admin

      session_id = SecureRandom.uuid
      SessionStore.create(
        session_id: session_id,
        admin_id: admin.id,
        created_at: Time.now,
        expires_at: Time.now + (24 * 60 * 60)
      )

      {
        status: 200,
        body: {
          message: 'Login successful',
          session_id: session_id,
          admin: {
            id: admin.id,
            username: admin.username
          }
        }.to_json
      }
    end

    def self.admin_logout(request)
      session_id = request.env['HTTP_AUTHORIZATION']&.split&.last

      if session_id
        SessionStore.delete(session_id)
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
      session = SessionStore.find_valid(session_id)
      return nil unless session

      admin = Admin.find_by_id(session['admin_id'])
      return nil unless admin

      Admin.new(id: admin.id, username: admin.username)
    end

    def self.create_log(request)
      request.body.rewind
      log_data = JSON.parse(request.body.read)

      log = SecurityLog.create_from_python_log(log_data)
      unless log
        return { status: 'rejected', error: 'Invalid log payload' }
      end

      SecurityAnalyzer.analyze_log(log)
      { status: 'received', log_id: log.id }
    rescue JSON::ParserError
      { status: 'error', error: 'Invalid JSON body' }
    end

    def self.get_logs
      { logs: SecurityLog.recent(limit: 100) }
    end

    def self.get_user_logs(user_id)
      { logs: SecurityLog.for_user(user_id, limit: 100) }
    end

    def self.get_alerts
      { alerts: Alert.recent(limit: 100).map(&:to_hash) }
    end

    def self.create_alert(request)
      request.body.rewind
      data = JSON.parse(request.body.read)
      payload = data.transform_keys { |k| k.to_sym }
      payload[:status] ||= 'new'
      payload[:timestamp] ||= Time.now.iso8601

      return { error: 'Invalid alert', status: 400 } unless Alert.validate_alert(payload)

      tid = Time.parse(payload[:timestamp].to_s)
      d = payload[:details] || {}
      details_str = d.is_a?(Hash) ? d.to_json : d.to_s

      id = DB[:alerts].insert(
        alert_type: payload[:alert_type].to_s,
        severity: payload[:severity].to_s,
        message: payload[:message].to_s,
        timestamp: tid,
        status: payload[:status].to_s,
        details: details_str
      )
      id ||= DB[:alerts].max(:id)
      inst = Alert.find_by_id(id)
      { alert: inst.to_hash }
    rescue JSON::ParserError
      { error: 'Invalid JSON body', status: 400 }
    rescue ArgumentError
      { error: 'Invalid timestamp', status: 400 }
    end

    def self.update_alert(alert_id, request)
      alert = Alert.find_by_id(alert_id)
      return { error: 'Alert not found', status: 404 } unless alert

      request.body.rewind
      update_data = JSON.parse(request.body.read)

      if update_data['status'] && Alert::STATUSES.include?(update_data['status'])
        Alert.update_status(alert_id, update_data['status'])
        { alert: Alert.find_by_id(alert_id).to_hash }
      else
        { error: 'Invalid status', status: 400 }
      end
    end

    def self.get_metrics
      metrics = {}
      Metric::METRIC_TYPES.each do |metric_type|
        metrics[metric_type] = Metric.get_latest_metrics(metric_type)
      end
      { metrics: metrics }
    end
  end
end
