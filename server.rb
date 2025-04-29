require 'sinatra/base'
require 'sinatra/json'
require 'sequel'
require 'java'
require_relative 'lib/ojdbc8-19.26.0.0.jar'
require 'dotenv'
require_relative 'settings/models/security_log'
require_relative 'settings/models/alert'
require_relative 'settings/models/metric'
require_relative 'settings/services/security_analyzer'
require_relative 'settings/endpoints'
require_relative 'settings/middleware'
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
      @oracle_service_name = ENV['ORACLE_SERVICE_NAME']
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
      "jdbc:oracle:thin:@#{@oracle_host}:#{@oracle_port}:#{@oracle_service_name}"
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

DB = SIEM::Database.connection

# Create schema if it doesn't exist
DB.execute("CREATE USER #{ENV['ORACLE_USERNAME']} IDENTIFIED BY #{ENV['ORACLE_PASSWORD']}") rescue nil
DB.execute("GRANT CONNECT, RESOURCE TO #{ENV['ORACLE_USERNAME']}") rescue nil

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
      set :bind, '0.0.0.0'
      set :port, ENV['PORT'] || 4567
      set :logging, true
      set :dump_errors, true
      set :show_exceptions, true
    end

    # =============================================
    # Route Definitions
    # =============================================
    get '/health' do
      Endpoints.health_check
    end

    post '/logs' do
      Endpoints.create_log(request)
    end

    get '/logs' do
      Endpoints.get_logs
    end

    get '/logs/user/:user_id' do
      Endpoints.get_user_logs(params[:user_id])
    end

    get '/alerts' do
      Endpoints.get_alerts
    end

    put '/alerts/:id' do
      Endpoints.update_alert(params[:id], request)
    end

    get '/metrics' do
      Endpoints.get_metrics
    end
  end
end