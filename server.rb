require 'sinatra'
require 'sinatra/json'
require 'sequel'
require 'dotenv'
require 'bcrypt'
require 'json'
require 'redis'
require 'digest'
require 'securerandom'
Dotenv.load

# =============================================
# Configuração global SIEM
# =============================================
module SIEM
  class Configuration
    attr_accessor :log_level, :alert_thresholds

    def initialize
      @log_level = ENV['LOG_LEVEL'] || 'info'

      @alert_thresholds = {
        failed_login_attempts: 5,
        suspicious_transaction_amount: 10_000,
        multiple_transactions_period: 300,
        multiple_transactions_count: 5
      }
    end
  end

  def self.config
    @config ||= Configuration.new
  end

  def self.configure
    yield(config) if block_given?
  end

  # =============================================
  # Oracle via JRuby + OJDBC (lib/ojdbc8-*.jar)
  # =============================================
  module Database
    OJDBC_JAR = File.expand_path('lib/ojdbc8-19.26.0.0.jar', __dir__)

    def self.connect
      unless defined?(JRUBY_VERSION)
        raise 'Este SIEM corre em JRuby para Oracle (OJDBC). Ex.: rbenv install "$(cat .ruby-version)" && rbenv local "$(cat .ruby-version)" && bundle install'
      end

      host = ENV.fetch('ORACLE_HOST', 'localhost')
      port = ENV.fetch('ORACLE_PORT', '1521')
      service = ENV.fetch('ORACLE_SERVICE_NAME', 'XEPDB1')
      user = ENV.fetch('ORACLE_USERNAME', 'siem')
      password = ENV.fetch('ORACLE_PASSWORD', 'siem')

      raise "OJDBC jar não encontrado: #{OJDBC_JAR}" unless File.exist?(OJDBC_JAR)

      require 'java'
      require OJDBC_JAR

      url = "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=#{host})(PORT=#{port}))(CONNECT_DATA=(SERVICE_NAME=#{service})))"
      Sequel.connect(url, user: user, password: password)
    end

    def self.connection
      connect
    end

    def self.test_connection(db)
      db.get(Sequel.lit('SELECT 1 FROM DUAL'))
      true
    end
  end
end

DB = SIEM::Database.connection

# Modelos e serviços
require_relative 'settings/models/security_log.rb'
require_relative 'settings/models/alert.rb'
require_relative 'settings/models/metric.rb'
require_relative 'settings/models/admin.rb'
require_relative 'settings/models/session_store.rb'
require_relative 'settings/services/security_analyzer.rb'
require_relative 'settings/services/response_automation.rb'
require_relative 'settings/services/ai_ml_analyzer.rb'
require_relative 'settings/services/threat_intelligence.rb'
require_relative 'settings/services/api_security.rb'
require_relative 'settings/services/tenant_manager.rb'
require_relative 'settings/services/mdr_service.rb'
require_relative 'settings/endpoints/endpoints.rb'
require_relative 'settings/middleware/middleware.rb'

# Initialize Redis connection
$redis = begin
  Redis.new(
    host: ENV['REDIS_HOST'] || 'localhost',
    port: ENV['REDIS_PORT'] || 6379,
    password: ENV['REDIS_PASSWORD']
  )
rescue StandardError
  nil
end

begin
  if DB[:admins].count.zero?
    pwd = ENV['ADMIN_PASSWORD'] || SecureRandom.alphanumeric(12)
    SIEM::Admin.create('admin', pwd)
    warn "[SIEM] Utilizador admin criado (username: admin, password: #{pwd})"
  end
rescue StandardError => e
  warn "[SIEM] Bootstrap admin ignorado: #{e.message}"
end

# Initialize services
SIEM::AIMLAnalyzer
SIEM::ThreatIntelligence
SIEM::APISecurity
SIEM::TenantManager
SIEM::MDRService

# =============================================
# Server Application
# =============================================
module SIEM
  class Server < Sinatra::Base
    # =============================================
    # Middleware Configuration
    # =============================================
    SIEM::Middleware.configure(self)

    helpers do
      def latest_metric_scalar(metric_type)
        hits = Metric.get_latest_metrics(metric_type, 1)
        return 0 if hits.nil? || hits.empty?
        v = hits.first['value'] || hits.first[:value]
        v.nil? ? 0 : v.to_f.round(1)
      end
    end

    configure do
      set :bind, ENV['HOST'] || '127.0.0.1'
      set :port, ENV['PORT'] || 4567
      set :logging, true
      set :dump_errors, true
      set :show_exceptions, true
      dashboard_dir = File.join(File.dirname(__FILE__), 'dashboard', 'public')
      set :views, dashboard_dir
      set :public_folder, dashboard_dir
      enable :sessions
      set :session_secret, ENV['SESSION_SECRET'] || SecureRandom.hex(64)
      enable :static

      set :data_sources, {
        network: { enabled: ENV['NETWORK_DATA_SOURCE_ENABLED'] == 'true', host: ENV['NETWORK_DATA_SOURCE_HOST'] },
        endpoint: { enabled: ENV['ENDPOINT_DATA_SOURCE_ENABLED'] == 'true', host: ENV['ENDPOINT_DATA_SOURCE_HOST'] },
        cloud: { enabled: ENV['CLOUD_DATA_SOURCE_ENABLED'] == 'true', api_key: ENV['CLOUD_DATA_SOURCE_API_KEY'] },
        xdr: { enabled: ENV['XDR_INTEGRATION_ENABLED'] == 'true', endpoint: ENV['XDR_INTEGRATION_ENDPOINT'], api_key: ENV['XDR_INTEGRATION_API_KEY'] },
        dlp: { enabled: ENV['DLP_INTEGRATION_ENABLED'] == 'true', endpoint: ENV['DLP_INTEGRATION_ENDPOINT'], api_key: ENV['DLP_INTEGRATION_API_KEY'] },
        mfa: { enabled: ENV['MFA_INTEGRATION_ENABLED'] == 'true', provider: ENV['MFA_INTEGRATION_PROVIDER'], config: ENV['MFA_INTEGRATION_CONFIG'] }
      }
      set :monitoring_interval, (ENV['MONITORING_INTERVAL'] || 60).to_i

      Thread.new do
        loop do
          interval = Server.settings.monitoring_interval
          Server.settings.data_sources.each do |source, config|
            next unless config[:enabled]

            warn "[SIEM] Collecting data from #{source}"
          end
          sleep interval.to_i
        end
      end

      before do
        next if request.path == '/health'
        next if request.path == '/login'
        next if request.path == '/auth/login'
        next if request.path == '/auth/logout'
        next if request.path == '/'
        next if request.path.start_with?('/dashboard')
        next if session[:admin_id] && request.path.start_with?('/api/')

        unless SIEM::APISecurity.validate_request(request)
          halt 401, { error: 'Unauthorized' }.to_json
        end
      end
    end

    # =============================================
    # Route Definitions
    # =============================================
    get '/login' do
      erb :login, layout: false
    end

    post '/auth/login' do
      result = Endpoints.login(request)
      if result[:success]
        session[:admin_id] = result[:admin_id]
        redirect '/dashboard'
      else
        @error = result[:message]
        erb :login, layout: false
      end
    end

    get '/auth/logout' do
      session.clear
      redirect '/login'
    end

    get '/dashboard' do
      unless session[:admin_id]
        redirect '/login'
      end

      @admin = Admin.find_by_id(session[:admin_id])
      unless @admin
        session.clear
        redirect '/login'
      end

      @metrics = {
        critical_count: Alert.count_by_severity('critical'),
        high_count: Alert.count_by_severity('high'),
        medium_count: Alert.count_by_severity('medium'),
        low_count: Alert.count_by_severity('low'),
        cpu_usage: latest_metric_scalar('cpu_usage'),
        memory_usage: latest_metric_scalar('memory_usage'),
        disk_usage: latest_metric_scalar('disk_usage')
      }

      @alerts = Alert.recent(limit: 10).map(&:to_hash)
      @logs = SecurityLog.recent(limit: 10)
      @activity_timeline = SecurityLog.hourly_activity_last_hours(24)

      erb :dashboard, layout: :layout
    end

    # Dashboard routes
    get '/dashboard/alerts' do
      authenticate_admin!
      @alerts = Alert.recent(limit: 200).map(&:to_hash)
      erb :alerts, layout: :layout
    end

    get '/dashboard/logs' do
      authenticate_admin!
      @logs = SecurityLog.recent(limit: 200)
      erb :logs, layout: :layout
    end

    get '/dashboard/metrics' do
      authenticate_admin!
      @metrics = {
        cpu_usage: Metric.get_latest_metrics('cpu_usage'),
        memory_usage: Metric.get_latest_metrics('memory_usage'),
        disk_usage: Metric.get_latest_metrics('disk_usage'),
        network_traffic: Metric.get_latest_metrics('network_traffic'),
        api_latency: Metric.get_latest_metrics('api_latency'),
        error_rate: Metric.get_latest_metrics('error_rate')
      }
      erb :metrics, layout: :layout
    end

    get '/dashboard/reports' do
      authenticate_admin!
      @report_types = [
        { id: 'security_incidents', name: 'Incidentes de Segurança' },
        { id: 'system_performance', name: 'Performance do Sistema' },
        { id: 'user_activity', name: 'Atividade dos Usuários' },
        { id: 'compliance', name: 'Conformidade' }
      ]
      erb :reports, layout: :layout
    end

    get '/dashboard/settings' do
      authenticate_admin!
      @settings = {
        alert_thresholds: SIEM.config.alert_thresholds,
        log_level: SIEM.config.log_level
      }
      erb :settings, layout: :layout
    end

    get '/dashboard/profile' do
      authenticate_admin!
      @admin = Admin.find_by_id(session[:admin_id])
      erb :profile, layout: :layout
    end

    get '/' do
      redirect '/dashboard'
    end

    get '/health' do
      begin
        SIEM::Database.test_connection(DB)
        { status: 'healthy', database: 'oracle' }.to_json
      rescue StandardError => e
        { status: 'unhealthy', error: e.message }.to_json
      end
    end

    post '/logs' do
      result = Endpoints.create_log(request)
      case result[:status]
      when 'rejected'
        status 422
      when 'error'
        status 400
      end
      json result
    end

    get '/logs' do
      json Endpoints.get_logs
    end

    get '/logs/user/:user_id' do
      json Endpoints.get_user_logs(params[:user_id])
    end

    get '/alerts' do
      json Endpoints.get_alerts
    end

    post '/alerts' do
      result = Endpoints.create_alert(request)
      status result[:status].to_i if result[:status]
      json result
    end

    before '/alerts' do
      authenticate_admin! unless request.request_method == 'POST'
    end

    put '/alerts/:id' do
      result = Endpoints.update_alert(params[:id], request)
      status result[:status].to_i if result[:status]
      json result
    end

    get '/metrics' do
      json Endpoints.get_metrics
    end

    # Admin authentication routes
    post '/admin/login' do
      content_type :json
      result = SIEM::Endpoints.admin_login(request)
      status result[:status]
      result[:body]
    end

    post '/admin/logout' do
      content_type :json
      result = SIEM::Endpoints.admin_logout(request)
      status result[:status]
      result[:body]
    end

    # Admin authentication middleware for protected routes
    def authenticate_admin!
      if session[:admin_id]
        @current_admin = Admin.find_by_id(session[:admin_id])
        unless @current_admin
          session.clear
          redirect '/login'
        end
        return
      end

      unless request.env['HTTP_AUTHORIZATION']
        halt 401, { error: 'No authorization header' }.to_json
      end

      session_id = request.env['HTTP_AUTHORIZATION'].split(' ').last
      admin = SIEM::Endpoints.verify_session(session_id)
      halt 401, { error: 'Invalid or expired session' }.to_json unless admin

      @current_admin = admin
    end

    # Protected admin routes
    before '/admin/*' do
      authenticate_admin! unless request.path_info == '/admin/login'
    end

    # Test protected route
    get '/admin/test' do
      content_type :json
      {
        message: "Protected route accessed successfully",
        admin: @current_admin.to_hash
      }.to_json
    end

    # VirusTotal Security Routes
    post '/api/virustotal/analyze-threat' do
      content_type :json

      begin
        file = params[:file]
        return { error: 'No file provided' }.to_json unless file

        # Save file temporarily
        temp_path = File.join(Dir.tmpdir, file[:filename])
        File.open(temp_path, 'wb') { |f| f.write(file[:tempfile].read) }

        # Análise completa a partir do ficheiro (hash + assinaturas + VirusTotal)
        result = SIEM::ThreatIntelligence.analyze_threat(temp_path)

        # Clean up
        File.delete(temp_path)

        result.to_json
      rescue => e
        { error: e.message }.to_json
      end
    end

    # Threat Analysis Routes
    post '/api/threat/analyze' do
      content_type :json

      begin
        file = params[:file]
        return { error: 'No file provided' }.to_json unless file

        # Save file temporarily
        temp_path = File.join(Dir.tmpdir, file[:filename])
        File.open(temp_path, 'wb') { |f| f.write(file[:tempfile].read) }

        # Analyze threat
        result = SIEM::ThreatIntelligence.analyze_threat(temp_path)

        # Clean up
        File.delete(temp_path)

        result.to_json
      rescue => e
        { error: e.message }.to_json
      end
    end
  end
end

# Start the server
SIEM::Server.run! if __FILE__ == $0