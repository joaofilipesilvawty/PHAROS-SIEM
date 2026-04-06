# frozen_string_literal: true

# Helpers de contadores OpsMon — alinhado a opsmon_runtime_metrics.py

module OPSMON
  module RuntimeMetrics
    module_function

    def inc_opsmon_log(tenant_id, level)
      OPSMON::InternalMetrics.inc_counter(
        'opsmon_logs_total',
        { 'tenant_id' => tenant_id.to_s, 'level' => level.to_s }
      )
    end

    def inc_opsmon_metric_insert(tenant_id, kind)
      OPSMON::InternalMetrics.inc_counter(
        'opsmon_metrics_insert_total',
        { 'tenant_id' => tenant_id.to_s, 'kind' => kind.to_s }
      )
    end

    def inc_opsmon_alert_created(tenant_id, severity)
      OPSMON::InternalMetrics.inc_counter(
        'opsmon_alerts_created_total',
        { 'tenant_id' => tenant_id.to_s, 'severity' => severity.to_s }
      )
    end

    def inc_opsmon_alert_acked(tenant_id)
      OPSMON::InternalMetrics.inc_counter(
        'opsmon_alerts_acked_total',
        { 'tenant_id' => tenant_id.to_s }
      )
    end

    def set_opsmon_component_health(tenant_id, component, healthy)
      OPSMON::InternalMetrics.set_gauge(
        'opsmon_component_health',
        healthy ? 1.0 : 0.0,
        { 'tenant_id' => tenant_id.to_s, 'component' => component.to_s }
      )
    end

    def inc_opsmon_cache_operation(tenant_id, operation, result)
      OPSMON::InternalMetrics.inc_counter(
        'opsmon_cache_operations_total',
        {
          'tenant_id' => tenant_id.to_s,
          'operation' => operation.to_s,
          'result' => result.to_s
        }
      )
    end

    def apply_health_gauges_from_components(tenant_id)
      OPSMON::Monitor.components_health.each do |component, ok|
        set_opsmon_component_health(tenant_id, component, ok)
      end
    end
  end
end
