# frozen_string_literal: true

# Operations Monitor — JRuby (stack PHAROS / OPSMON)
# Alinhado a SETTINGS/SHARED/OBSERVABILITY/OPSMON (Pryden): health, internal_metrics, chart_series.
#
# `module OPSMON` reabre o namespace definido em server.rb; aqui só vive `Monitor`.

module OPSMON
  module Monitor
    STARTED_AT = Time.now.freeze

    module_function

    def check_oracle
      OPSMON::Database.test_connection(DB)
      true
    rescue StandardError
      false
    end

    def check_redis
      return false unless $redis

      $redis.ping == 'PONG'
    rescue StandardError
      false
    end

    def components_health
      {
        oracle: check_oracle,
        redis: check_redis
      }
    end

    def overall_status(components)
      vals = components.values
      return 'error' if vals.empty?

      vals.all? ? 'healthy' : 'degraded'
    end

    def health_check
      ch = components_health
      ok = ch.values.all?
      {
        status: ok ? 'healthy' : 'unhealthy',
        timestamp: Time.now.utc.iso8601,
        tenant_id: 'default',
        overall: ok ? 'healthy' : 'unhealthy',
        components: ch,
        database: ch[:oracle],
        redis: ch[:redis]
      }
    end

    def system_status
      ch = components_health
      uptime_seconds = (Time.now - STARTED_AT).to_i
      {
        status: overall_status(ch),
        timestamp: Time.now.utc.iso8601,
        tenant_id: 'default',
        uptime_seconds: uptime_seconds,
        services: ch,
        health: ch,
        started_at: STARTED_AT.getutc.iso8601
      }
    end

    def ruby_vm_metrics
      out = {
        uptime_seconds: (Time.now - STARTED_AT).to_i,
        ruby_version: RUBY_VERSION,
        jruby_version: (defined?(JRUBY_VERSION) ? JRUBY_VERSION : nil),
        gc_stat: GC.stat
      }

      if defined?(JRUBY_VERSION) && defined?(Java)
        rt = Java::JavaLang::Runtime.getRuntime
        used = rt.totalMemory - rt.freeMemory
        out[:jvm_heap_used_mb] = (used / 1024.0 / 1024.0).round(2)
        out[:jvm_heap_committed_mb] = (rt.totalMemory / 1024.0 / 1024.0).round(2)
        out[:jvm_heap_max_mb] = (rt.maxMemory / 1024.0 / 1024.0).round(2)
      end

      out
    end

    # Igual ao GET .../dashboard/snapshot do Pryden: health + runtime_metrics (counters/gauges) + chart_series.
    def dashboard_snapshot(tenant_id: 'default')
      OPSMON::ProcessRuntimeGauges.refresh
      OPSMON::RuntimeMetrics.apply_health_gauges_from_components(tenant_id)

      health = begin
        health_check
      rescue StandardError => e
        {
          'status' => 'error',
          'error' => e.message,
          'tenant_id' => tenant_id,
          'timestamp' => Time.now.utc.iso8601
        }
      end

      internal = OPSMON::InternalMetrics.snapshot
      OPSMON::InternalMetricsHistory.record_runtime_sample(internal)

      {
        timestamp: Time.now.utc.iso8601,
        tenant_id: tenant_id,
        health: health,
        runtime_metrics: internal,
        chart_series: OPSMON::InternalMetricsHistory.chart_series,
        ruby_vm: ruby_vm_metrics
      }
    end

    # Resposta legada: só health + métricas VM (sem internal_metrics).
    def snapshot
      {
        timestamp: Time.now.utc.iso8601,
        tenant_id: 'default',
        health: health_check,
        runtime_metrics: ruby_vm_metrics
      }
    end

    # Snapshot completo (recomendado; mesmo conteúdo que dashboard_snapshot).
    def full_snapshot(tenant_id: 'default')
      dashboard_snapshot(tenant_id: tenant_id)
    end
  end
end