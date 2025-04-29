require 'sinatra/base'
require 'sinatra/json'
require 'sequel'
require 'java'
require_relative 'lib/ojdbc8-19.26.0.0.jar'
require 'dotenv'
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
      enable :static
    end

    # =============================================
    # Route Definitions
    # =============================================
    get '/' do
      erb :dashboard, layout: :layout
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
  end
end

# Start the server
SIEM::Server.run!