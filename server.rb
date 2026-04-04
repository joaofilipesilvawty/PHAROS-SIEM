require 'sinatra'
require 'sinatra/json'
require 'opensearch'
require 'dotenv'
require 'bcrypt'
require 'json'
require 'redis'
require 'digest'
require 'securerandom'
Dotenv.load

# =============================================
# DATABASE CONFIGURATION Module
# =============================================
module SIEM
  class Configuration
    attr_accessor :opensearch_host, :opensearch_port,
                  :opensearch_username, :opensearch_password,
                  :log_level, :alert_thresholds

    def initialize
      @opensearch_host = ENV['OPENSEARCH_HOST'] || 'localhost'
      @opensearch_port = ENV['OPENSEARCH_PORT'] || '9200'
      @opensearch_username = ENV['OPENSEARCH_USERNAME'] || 'admin'
      @opensearch_password = ENV['OPENSEARCH_PASSWORD'] || 'admin'
      @log_level = ENV['LOG_LEVEL'] || 'info'

      @alert_thresholds = {
        failed_login_attempts: 5,
        suspicious_transaction_amount: 10000,
        multiple_transactions_period: 300,
        multiple_transactions_count: 5
      }
    end

    def opensearch_url
      "http://#{@opensearch_host}:#{@opensearch_port}"
    end
  end

  def self.config
    @config ||= Configuration.new
  end

  def self.configure
    yield(config) if block_given?
  end

  module Database
    def self.connect
      host = ENV['OPENSEARCH_HOST'] || 'localhost'
      port = ENV['OPENSEARCH_PORT'] || '9200'
      username = ENV['OPENSEARCH_USERNAME'] || 'admin'
      password = ENV['OPENSEARCH_PASSWORD'] || 'admin'

      $OS = OpenSearch::Client.new(
        host: "https://#{host}:#{port}",
        user: username,
        password: password,
        transport_options: {
          ssl: {
            verify: false,
            ca_file: nil
          },
          headers: {
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
          }
        },
        retry_on_failure: 3,
        request_timeout: 30,
        ssl_verify: false
      )
    end

    def self.connection
      connect
    end

    def self.create_indices
      client = connection
      indices = {
        admins: {
          mappings: {
            properties: {
              username: { type: 'keyword' },
              password_hash: { type: 'keyword' },
              created_at: { type: 'date' },
              updated_at: { type: 'date' }
            }
          }
        },
        sessions: {
          mappings: {
            properties: {
              id: { type: 'keyword' },
              admin_id: { type: 'keyword' },
              created_at: { type: 'date' },
              expires_at: { type: 'date' }
            }
          }
        },
        security_logs: {
          mappings: {
            properties: {
              event_type: { type: 'keyword' },
              source: { type: 'keyword' },
              severity: { type: 'keyword' },
              message: { type: 'text' },
              timestamp: { type: 'date' },
              user_id: { type: 'keyword' },
              ip_address: { type: 'ip' },
              details: { type: 'text' }
            }
          }
        },
        alerts: {
          mappings: {
            properties: {
              alert_type: { type: 'keyword' },
              severity: { type: 'keyword' },
              message: { type: 'text' },
              timestamp: { type: 'date' },
              status: { type: 'keyword' },
              details: { type: 'text' }
            }
          }
        },
        metrics: {
          mappings: {
            properties: {
              metric_type: { type: 'keyword' },
              value: { type: 'float' },
              timestamp: { type: 'date' },
              source: { type: 'keyword' }
            }
          }
        }
      }

      indices.each do |index_name, settings|
        unless client.indices.exists?(index: index_name)
          client.indices.create(
            index: index_name,
            body: settings
          )
        end
      end
    end
  end
end

# Initialize database connection
OS = SIEM::Database.connection
ES = OS

# Create indices if they don't exist
SIEM::Database.create_indices

# Now load the models and other dependencies
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
  if ES.count(index: 'admins', body: { query: { match_all: {} } })['count'].to_i.zero?
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
      setup_data_sources
      setup_real_time_monitoring
      setup_compliance_and_retention
      setup_api_security
    end

    # =============================================
    # Route Definitions
    # =============================================
    get '/login' do
      erb :login
    end

    post '/auth/login' do
      result = Endpoints.login(request)
      if result[:success]
        session[:admin_id] = result[:admin_id]
        redirect '/dashboard'
      else
        @error = result[:message]
        erb :login
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
        OS.cluster.health
        { status: 'healthy' }.to_json
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

    # Multi-Source Data Collection Setup
    def setup_data_sources
      @data_sources = {
        network: { enabled: ENV['NETWORK_DATA_SOURCE_ENABLED'] == 'true', host: ENV['NETWORK_DATA_SOURCE_HOST'] },
        endpoint: { enabled: ENV['ENDPOINT_DATA_SOURCE_ENABLED'] == 'true', host: ENV['ENDPOINT_DATA_SOURCE_HOST'] },
        cloud: { enabled: ENV['CLOUD_DATA_SOURCE_ENABLED'] == 'true', api_key: ENV['CLOUD_DATA_SOURCE_API_KEY'] },
        xdr: { enabled: ENV['XDR_INTEGRATION_ENABLED'] == 'true', endpoint: ENV['XDR_INTEGRATION_ENDPOINT'], api_key: ENV['XDR_INTEGRATION_API_KEY'] },
        dlp: { enabled: ENV['DLP_INTEGRATION_ENABLED'] == 'true', endpoint: ENV['DLP_INTEGRATION_ENDPOINT'], api_key: ENV['DLP_INTEGRATION_API_KEY'] },
        mfa: { enabled: ENV['MFA_INTEGRATION_ENABLED'] == 'true', provider: ENV['MFA_INTEGRATION_PROVIDER'], config: ENV['MFA_INTEGRATION_CONFIG'] }
      }
    end

    # Real-Time Monitoring Configuration
    def setup_real_time_monitoring
      @monitoring_interval = ENV['MONITORING_INTERVAL'] || 60
      Thread.new do
        loop do
          collect_data_from_sources
          sleep @monitoring_interval.to_i
        end
      end
    end

    def collect_data_from_sources
      @data_sources.each do |source, config|
        next unless config[:enabled]
        # Placeholder for data collection logic
        puts "Collecting data from #{source}"
      end
    end

    def setup_compliance_and_retention
      # Implement compliance and retention logic
    end

    def setup_api_security
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