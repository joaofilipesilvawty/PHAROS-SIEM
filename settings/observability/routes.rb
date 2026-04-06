# frozen_string_literal: true

# Rotas HTTP OpsMon — alinhado a opsmon_router.py (Pryden).
require 'time'

module OPSMON
  module WebRoutes
    UI_DIR = File.join(__dir__, 'ui')

    def self.registered(app)
      # Recebe o Rack request da rota Sinatra — não usar `request` dentro de lambda sem argumento
      # (NameError: request no módulo WebRoutes).
      parse_json = lambda do |req|
        req.body.rewind
        raw = req.body.read.to_s
        raw.empty? ? {} : JSON.parse(raw)
      rescue JSON::ParserError
        nil
      end

      app.get '/opsmon/health' do
        content_type :json
        OPSMON::Monitor.health_check.to_json
      end

      app.get '/opsmon/status' do
        content_type :json
        OPSMON::Monitor.system_status.to_json
      end

      # Snapshot completo (health + internal_metrics + chart_series + ruby_vm) — igual Pryden dashboard/snapshot.
      app.get '/opsmon/snapshot' do
        content_type :json
        tenant = params['tenant_id'] || 'default'
        OPSMON::Monitor.dashboard_snapshot(tenant_id: tenant).to_json
      end

      app.get '/opsmon/dashboard/snapshot' do
        content_type :json
        headers['Cache-Control'] = 'no-store'
        tenant = params['tenant_id'] || 'default'
        OPSMON::Monitor.dashboard_snapshot(tenant_id: tenant).to_json
      end

      app.get '/opsmon/dashboard/ui' do
        content_type :html
        headers['Cache-Control'] = 'no-store'
        path = File.join(UI_DIR, 'public', 'dashboard.html')
        halt 404, 'UI não encontrada' unless File.file?(path)

        File.read(path, encoding: 'UTF-8')
      end

      opsmon_dashboard_js = lambda do
        content_type 'application/javascript; charset=utf-8'
        headers['Cache-Control'] = 'no-store'
        path = File.join(UI_DIR, 'public', 'js', 'app.js')
        halt 404 unless File.file?(path)

        File.read(path, encoding: 'UTF-8')
      end

      app.get '/opsmon/dashboard/app.js', &opsmon_dashboard_js
      app.get '/opsmon/dashboard/dashboard.js', &opsmon_dashboard_js

      app.get '/opsmon/dashboard/styles.css' do
        content_type 'text/css; charset=utf-8'
        headers['Cache-Control'] = 'no-store'
        path = File.join(UI_DIR, 'public', 'css', 'styles.css')
        halt 404 unless File.file?(path)

        File.read(path, encoding: 'UTF-8')
      end

      # Logs
      app.get '/opsmon/logs' do
        content_type :json
        limit = [[params['limit'].to_i, 1].max, 1000].min
        severity = params['severity'].to_s.strip
        rows = SecurityLog.recent(limit: limit)
        rows = rows.select { |r| r[:severity].to_s == severity } unless severity.empty?
        { logs: rows }.to_json
      end

      app.post '/opsmon/logs/:level' do
        content_type :json
        level = params['level'].to_s.downcase
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?

        severity = case level
                   when 'debug', 'info' then 'low'
                   when 'warning', 'warn' then 'medium'
                   when 'error' then 'high'
                   when 'critical' then 'critical'
                   else 'low'
                   end
        event_type = %w[error critical].include?(level) ? 'system_error' : 'user_behavior'
        message = payload['message'].to_s
        halt 422, { error: 'message é obrigatório' }.to_json if message.strip.empty?

        log = SecurityLog.create_from_python_log(
          'event_type' => event_type,
          'source' => payload['module'].to_s.empty? ? 'opsmon' : payload['module'].to_s,
          'severity' => severity,
          'message' => message,
          'timestamp' => Time.now.iso8601,
          'user_id' => payload['user_id'].to_s,
          'ip_address' => request.ip.to_s,
          'details' => payload['metadata'].is_a?(Hash) ? payload['metadata'] : {}
        )

        if log.nil?
          halt 422, { error: 'Invalid log payload' }.to_json
        end

        OPSMON::RuntimeMetrics.inc_opsmon_log('default', severity)
        { success: true, log_id: log.id }.to_json
      end

      # Alerts
      app.get '/opsmon/alerts' do
        content_type :json
        Endpoints.get_alerts.to_json
      end

      app.post '/opsmon/alerts' do
        content_type :json
        result = Endpoints.create_alert(request)
        status result[:status].to_i if result[:status]
        result.to_json
      end

      app.put '/opsmon/alerts/:id' do
        content_type :json
        result = Endpoints.update_alert(params['id'], request)
        status result[:status].to_i if result[:status]
        result.to_json
      end

      # Metrics
      app.post '/opsmon/metrics/collect' do
        content_type :json
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?

        name = payload['name'].to_s
        value = payload['value']
        source = payload['source'].to_s.empty? ? 'opsmon_api' : payload['source'].to_s

        halt 422, { error: 'name é obrigatório' }.to_json if name.empty?
        halt 422, { error: 'value é obrigatório' }.to_json if value.nil?

        id = Metric.record_metric(name, value, source)
        if id.nil?
          halt 422, { error: 'metric inválida para este sistema' }.to_json
        end

        { success: true, metric_id: id }.to_json
      end

      app.get '/opsmon/metrics' do
        content_type :json
        metric_name = params['metric_name'].to_s.strip
        limit = [[params['limit'].to_i, 1].max, 1000].min
        if metric_name.empty?
          payload = {}
          Metric::METRIC_TYPES.each do |t|
            payload[t] = Metric.get_latest_metrics(t, limit)
          end
          { metrics: payload }.to_json
        else
          { metrics: Metric.get_latest_metrics(metric_name, limit) }.to_json
        end
      end

      app.get '/opsmon/metrics/summary/:metric_name' do
        content_type :json
        metric_name = params['metric_name'].to_s
        limit = [[params['limit'].to_i, 1].max, 10_000].min
        rows = Metric.get_latest_metrics(metric_name, limit)
        values = rows.map { |r| r['value'].to_f }
        if values.empty?
          halt 404, { error: 'No metrics found for this metric_name' }.to_json
        end

        {
          metric_name: metric_name,
          count: values.size,
          min: values.min,
          max: values.max,
          avg: (values.sum / values.size.to_f),
          latest: rows.first
        }.to_json
      end

      # Cache
      app.post '/opsmon/cache/set' do
        content_type :json
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?
        halt 503, { error: 'Redis unavailable' }.to_json unless $redis

        key = payload['key'].to_s
        val = payload['value']
        ttl = payload['ttl_seconds'].to_i
        halt 422, { error: 'key é obrigatório' }.to_json if key.empty?

        if ttl.positive?
          $redis.setex(key, ttl, val.to_s)
        else
          $redis.set(key, val.to_s)
        end
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'set', 'ok')
        { success: true }.to_json
      rescue StandardError => e
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'set', 'error')
        halt 500, { error: e.message }.to_json
      end

      app.get '/opsmon/cache/get/:key' do
        content_type :json
        halt 503, { error: 'Redis unavailable' }.to_json unless $redis
        key = params['key'].to_s
        value = $redis.get(key)
        if value.nil?
          OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'get', 'miss')
          halt 404, { error: 'Cache entry not found' }.to_json
        end
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'get', 'hit')
        { key: key, value: value }.to_json
      rescue StandardError => e
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'get', 'error')
        halt 500, { error: e.message }.to_json
      end

      app.delete '/opsmon/cache/delete/:key' do
        content_type :json
        halt 503, { error: 'Redis unavailable' }.to_json unless $redis
        deleted = $redis.del(params['key'].to_s)
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'delete', deleted.positive? ? 'hit' : 'miss')
        { success: deleted.positive? }.to_json
      rescue StandardError => e
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'delete', 'error')
        halt 500, { error: e.message }.to_json
      end

      app.delete '/opsmon/cache/clear' do
        content_type :json
        halt 503, { error: 'Redis unavailable' }.to_json unless $redis
        $redis.flushdb
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'clear', 'ok')
        { success: true }.to_json
      rescue StandardError => e
        OPSMON::RuntimeMetrics.inc_opsmon_cache_operation('default', 'clear', 'error')
        halt 500, { error: e.message }.to_json
      end

      app.get '/opsmon/cache/stats' do
        content_type :json
        halt 503, { error: 'Redis unavailable' }.to_json unless $redis
        info = $redis.info
        {
          connected_clients: info['connected_clients'].to_i,
          used_memory_human: info['used_memory_human'],
          keyspace_hits: info['keyspace_hits'].to_i,
          keyspace_misses: info['keyspace_misses'].to_i
        }.to_json
      rescue StandardError => e
        halt 500, { error: e.message }.to_json
      end

      # Infrastructure
      app.post '/opsmon/infrastructure/system-metrics' do
        content_type :json
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?

        records = {
          'cpu_usage' => payload['cpu_usage'],
          'memory_usage' => payload['memory_usage'],
          'disk_usage' => payload['disk_usage'],
          'network_traffic' => payload['network_traffic']
        }
        ids = {}
        records.each do |name, value|
          next if value.nil?

          id = Metric.record_metric(name, value, 'opsmon_infrastructure')
          ids[name] = id if id
        end
        { success: true, metrics: ids }.to_json
      end

      app.post '/opsmon/infrastructure/process-info' do
        content_type :json
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?

        cpu = payload['cpu_percent']
        mem = payload['memory_percent']
        status = payload['status'].to_s
        OPSMON::InternalMetrics.set_gauge('process_cpu_percent', cpu.to_f) unless cpu.nil?
        OPSMON::InternalMetrics.set_gauge('process_memory_percent', mem.to_f) unless mem.nil?
        OPSMON::InternalMetrics.set_gauge('process_status_up', (status == 'running' ? 1.0 : 0.0))

        { success: true }.to_json
      end

      # Cleanup
      app.post '/opsmon/cleanup' do
        content_type :json
        days = [[params['days'].to_i, 1].max, 365].min
        cutoff = Time.now - (days * 86_400)

        results = {}
        results[:security_logs] = DB[:security_logs].where { timestamp < cutoff }.delete
        results[:alerts] = DB[:alerts].where { timestamp < cutoff }.delete
        results[:metrics] = DB[:metrics].where { timestamp < cutoff }.delete
        results[:sessions] = DB[:sessions].where { expires_at < Time.now }.delete

        { success: true, days: days, deleted: results }.to_json
      end

      # Feature flags (sem OTP)
      app.get '/opsmon/feature-flags/' do
        content_type :json
        OPSMON::FeatureFlags.all.to_json
      end

      app.get '/opsmon/feature-flags/:name' do
        content_type :json
        flag = OPSMON::FeatureFlags.get(params['name'])
        halt 404, { error: 'Feature flag não encontrado' }.to_json if flag.nil?
        flag.to_json
      end

      app.post '/opsmon/feature-flags/' do
        content_type :json
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?
        flag = OPSMON::FeatureFlags.create(payload)
        status 201
        flag.to_json
      rescue ArgumentError => e
        halt 409, { error: e.message }.to_json
      end

      app.put '/opsmon/feature-flags/:name' do
        content_type :json
        payload = parse_json.call(request)
        halt 400, { error: 'Invalid JSON body' }.to_json if payload.nil?
        flag = OPSMON::FeatureFlags.update(params['name'], payload)
        halt 404, { error: 'Feature flag não encontrado' }.to_json if flag.nil?
        flag.to_json
      end

      app.post '/opsmon/feature-flags/:name/enable' do
        content_type :json
        flag = OPSMON::FeatureFlags.set_enabled(params['name'], true)
        halt 404, { error: 'Feature flag não encontrado' }.to_json if flag.nil?
        flag.to_json
      end

      app.post '/opsmon/feature-flags/:name/disable' do
        content_type :json
        flag = OPSMON::FeatureFlags.set_enabled(params['name'], false)
        halt 404, { error: 'Feature flag não encontrado' }.to_json if flag.nil?
        flag.to_json
      end

      app.post '/opsmon/feature-flags/:name/rollout' do
        content_type :json
        percentage = params['percentage'].to_i
        flag = OPSMON::FeatureFlags.set_rollout(params['name'], percentage)
        halt 404, { error: 'Feature flag não encontrado' }.to_json if flag.nil?
        flag.to_json
      end

      app.delete '/opsmon/feature-flags/:name' do
        content_type :json
        flag = OPSMON::FeatureFlags.deprecate(params['name'])
        halt 404, { error: 'Feature flag não encontrado' }.to_json if flag.nil?
        status 204
      end
    end
  end
end
