require 'sinatra/base'
require 'sinatra/json'
require 'sequel'
require 'java'
require_relative 'lib/ojdbc8-19.26.0.0.jar'
require 'dotenv'
require 'bcrypt'
require 'json'
Dotenv.load

# =============================================
# DATABASE CONFIGURATION Module
# =============================================
module SIEM
  class Configuration
    attr_accessor :oracle_host, :oracle_port, :oracle_service_name,
                  :oracle_username, :oracle_password,
                  :log_level, :alert_thresholds

    def initialize
      @oracle_host = ENV['ORACLE_HOST']
      @oracle_port = ENV['ORACLE_PORT'] || '1521'
      @oracle_service_name = ENV['ORACLE_SERVICE_NAME'] || 'orclpdb1'
      @oracle_username = ENV['ORACLE_USERNAME']
      @oracle_password = ENV['ORACLE_PASSWORD']
      @log_level = ENV['LOG_LEVEL'] || 'info'

      @alert_thresholds = {
        failed_login_attempts: 5,
        suspicious_transaction_amount: 10000,
        multiple_transactions_period: 300,
        multiple_transactions_count: 5
      }
    end

    def oracle_connection_string
      "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=#{@oracle_host})(PORT=#{@oracle_port}))(CONNECT_DATA=(SERVICE_NAME=#{@oracle_service_name})))"
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
      @connection ||= Sequel.connect(
        adapter: 'jdbc',
        driver: 'oracle.jdbc.driver.OracleDriver',
        url: SIEM.config.oracle_connection_string,
        user: SIEM.config.oracle_username,
        password: SIEM.config.oracle_password
      )
    end

    def self.connection
      connect
    end
  end
end

# Initialize database connection
DB = SIEM::Database.connection

# Create schema if it doesn't exist
DB.execute("CREATE USER #{ENV['ORACLE_USERNAME']} IDENTIFIED BY #{ENV['ORACLE_PASSWORD']}") rescue nil
DB.execute("GRANT CONNECT, RESOURCE TO #{ENV['ORACLE_USERNAME']}") rescue nil

# Create tables if they don't exist
DB.create_table? :admins do
  primary_key :id
  String :username, size: 50, null: false, unique: true
  String :password_hash, size: 100, null: false
  DateTime :created_at
  DateTime :updated_at
end

DB.create_table? :sessions do
  String :id, primary_key: true
  foreign_key :admin_id, :admins
  DateTime :created_at, null: false
  DateTime :expires_at, null: false
end

DB.create_table? :security_logs do
  primary_key :id
  String :event_type, size: 50
  String :source, size: 100
  String :severity, size: 20
  String :message, text: true
  DateTime :timestamp
  String :user_id, size: 50
  String :ip_address, size: 45
  String :details, text: true
end

DB.create_table? :alerts do
  primary_key :id
  String :alert_type, size: 50
  String :severity, size: 20
  String :message, text: true
  DateTime :timestamp
  String :status, size: 20
  String :details, text: true
end

DB.create_table? :metrics do
  primary_key :id
  String :metric_type, size: 50
  Float :value
  DateTime :timestamp
  String :source, size: 100
end

# Now load the models and other dependencies
require_relative 'settings/models/security_log.rb'
require_relative 'settings/models/alert.rb'
require_relative 'settings/models/metric.rb'
require_relative 'settings/models/admin.rb'
require_relative 'settings/services/security_analyzer.rb'
require_relative 'settings/endpoints/endpoints.rb'
require_relative 'settings/middleware/middleware.rb'

# =============================================
# Server Application
# =============================================
module SIEM
  class Server < Sinatra::Base
    # =============================================
    # Middleware Configuration
    # =============================================
    SIEM::Middleware.configure(self)

    configure do
      set :bind, '127.0.0.1'
      set :port, ENV['PORT'] || 4567
      set :logging, true
      set :dump_errors, true
      set :show_exceptions, true
      set :views, File.join(File.dirname(__FILE__), 'dashboard/templates')
      set :public_folder, File.join(File.dirname(__FILE__), 'dashboard/templates')
      enable :sessions
      set :session_secret, ENV['SESSION_SECRET'] || 'a_very_long_and_secure_secret_key_that_is_at_least_64_characters_long_for_development_only_9876543210'
      enable :static
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

      @admin = DB[:admins][id: session[:admin_id]]
      unless @admin
        session.clear
        redirect '/login'
      end

      @metrics = {
        critical_count: Alert.where(severity: 'Critical').count,
        high_count: Alert.where(severity: 'High').count,
        medium_count: Alert.where(severity: 'Medium').count,
        low_count: Alert.where(severity: 'Low').count,
        cpu_usage: Metric.get_latest_metrics('cpu_usage'),
        memory_usage: Metric.get_latest_metrics('memory_usage'),
        disk_usage: Metric.get_latest_metrics('disk_usage')
      }

      @alerts = Alert.order(Sequel.desc(:timestamp)).limit(10).map(&:to_hash)
      @logs = SecurityLog.order(Sequel.desc(:timestamp)).limit(10).map(&:to_hash)

      # Dados para o gráfico de timeline
      timeline_data = SecurityLog
        .where { timestamp > Sequel.lit("SYSDATE - 1") }
        .group_and_count(Sequel.function(:TO_CHAR, :timestamp, 'YYYY-MM-DD HH24:00:00'))
        .order(Sequel.function(:TO_CHAR, :timestamp, 'YYYY-MM-DD HH24:00:00'))
        .all

      @activity_timeline = {
        labels: timeline_data.map { |d| d[:to_char] },
        data: timeline_data.map { |d| d[:count] }
      }

      erb :dashboard, layout: :layout
    end

    # Dashboard routes
    get '/dashboard/alerts' do
      authenticate_admin!
      @alerts = Alert.order(Sequel.desc(:timestamp)).map(&:to_hash)
      erb :alerts, layout: :layout
    end

    get '/dashboard/logs' do
      authenticate_admin!
      @logs = SecurityLog.order(Sequel.desc(:timestamp)).map(&:to_hash)
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
      @admin = DB[:admins][id: session[:admin_id]]
      erb :profile, layout: :layout
    end

    get '/' do
      redirect '/dashboard'
    end

    get '/health' do
      json Endpoints.health_check
    end

    post '/logs' do
      json Endpoints.create_log(request)
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

    put '/alerts/:id' do
      json Endpoints.update_alert(params[:id], request)
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
      return halt 401, { error: 'No authorization header' }.to_json unless request.env['HTTP_AUTHORIZATION']

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
  end
end

# Start the server
SIEM::Server.run!