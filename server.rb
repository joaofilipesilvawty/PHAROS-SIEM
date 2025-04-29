require 'sinatra/base'
require 'sinatra/json'
require 'rack/cors'
require_relative 'settings/database/database'
require_relative 'settings/models/security_log'
require_relative 'settings/models/alert'
require_relative 'settings/models/metric'
require_relative 'settings/services/security_analyzer'

module SIEM
  class Server < Sinatra::Base
    use Rack::Cors do
      allow do
        origins '*'
        resource '*', headers: :any, methods: [:get, :post, :put, :delete, :options]
      end
    end

    configure do
      set :bind, '0.0.0.0'
      set :port, ENV['PORT'] || 4567
      set :logging, true
      set :dump_errors, true
      set :show_exceptions, true
    end

    # Health check endpoint
    get '/health' do
      begin
        # Verifica conexão com o Oracle
        DB.test_connection
        json status: 'healthy', database: 'connected'
      rescue => e
        json status: 'unhealthy', error: e.message
      end
    end

    # Endpoint para receber logs de segurança
    post '/logs' do
      request.body.rewind
      log_data = JSON.parse(request.body.read)

      # Criar log de segurança
      log = SecurityLog.create_from_python_log(log_data)

      # Analisar o log e gerar alertas se necessário
      SecurityAnalyzer.analyze_log(log)

      json status: 'received', log_id: log.id
    end

    # Endpoint para consultar alertas
    get '/alerts' do
      alerts = Alert.order(Sequel.desc(:timestamp)).limit(100).all
      json alerts: alerts.map(&:to_hash)
    end

    # Endpoint para consultar métricas
    get '/metrics' do
      metrics = {}
      Metric::METRIC_TYPES.each do |metric_type|
        metrics[metric_type] = Metric.get_latest_metrics(metric_type)
      end
      json metrics: metrics
    end

    # Endpoint para atualizar status de alerta
    put '/alerts/:id' do
      alert = Alert[params[:id]]
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

    # Endpoint para consultar logs
    get '/logs' do
      logs = SecurityLog.order(Sequel.desc(:timestamp)).limit(100).all
      json logs: logs.map(&:to_hash)
    end

    # Endpoint para consultar logs por usuário
    get '/logs/user/:user_id' do
      logs = SecurityLog
        .where(user_id: params[:user_id])
        .order(Sequel.desc(:timestamp))
        .limit(100)
        .all
      json logs: logs.map(&:to_hash)
    end
  end
end