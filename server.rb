require 'sinatra'
require 'sinatra/json'
require 'opensearch'
require 'dotenv'
require 'bcrypt'
require 'json'
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

# Create indices if they don't exist
SIEM::Database.create_indices

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
      set :bind, ENV['HOST'] || '127.0.0.1'
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

      @admin = OS[:admins][id: session[:admin_id]]
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
      @admin = OS[:admins][id: session[:admin_id]]
      erb :profile, layout: :layout
    end

    get '/' do
      redirect '/dashboard'
    end

    get '/health' do
      begin
        client = self.class.connect_to_opensearch
        client.cluster.health
        { status: 'healthy' }.to_json
      rescue => e
        { status: 'unhealthy', error: e.message }.to_json
      end
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

    def self.connect_to_opensearch
      host = ENV['OPENSEARCH_HOST'] || 'localhost'
      port = ENV['OPENSEARCH_PORT'] || '9200'
      username = ENV['OPENSEARCH_USERNAME'] || 'admin'
      password = ENV['OPENSEARCH_PASSWORD'] || 'admin'

      @client ||= OpenSearch::Client.new(
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

    def self.create_indices
      indices = {
        'logs' => {
          mappings: {
            properties: {
              timestamp: { type: 'date' },
              level: { type: 'keyword' },
              message: { type: 'text' },
              source: { type: 'keyword' }
            }
          }
        },
        'alerts' => {
          mappings: {
            properties: {
              timestamp: { type: 'date' },
              type: { type: 'keyword' },
              severity: { type: 'keyword' },
              message: { type: 'text' },
              source_ip: { type: 'ip' },
              details: { type: 'object' }
            }
          }
        }
      }

      indices.each do |index_name, settings|
        unless @client.indices.exists?(index: index_name)
          @client.indices.create(
            index: index_name,
            body: settings
          )
        end
      end
    end

    # Initialize OpenSearch connection and create indices
    configure do
      connect_to_opensearch
      create_indices
    end
  end
end

# Start the server
SIEM::Server.run! if __FILE__ == $0