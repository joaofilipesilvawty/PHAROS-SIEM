# frozen_string_literal: true

# Métricas em memória (thread-safe) — alinhado a SETTINGS/SHARED/OBSERVABILITY/internal_metrics.py
# Contadores e gauges com labels; expostos via snapshot do dashboard OpsMon.

module OPSMON
  module InternalMetrics
    @lock = Mutex.new
    @counters = {}
    @gauges = {}

    class << self
      def norm_labels(labels)
        return [] if labels.nil? || (labels.respond_to?(:empty?) && labels.empty?)

        h = labels.is_a?(Hash) ? labels : {}
        h.transform_keys(&:to_s).sort.map { |k, v| [k.to_s, v.to_s] }
      end

      def counter_key(metric, labels)
        [metric.to_s, norm_labels(labels)]
      end

      def inc_counter(metric, labels = nil, amount = 1.0)
        k = counter_key(metric, labels)
        @lock.synchronize do
          @counters[k] = (@counters[k] || 0.0) + amount.to_f
        end
      end

      def set_gauge(metric, value, labels = nil)
        k = counter_key(metric, labels)
        @lock.synchronize do
          @gauges[k] = value.to_f
        end
      end

      def get_counter_value(metric, labels = nil)
        k = counter_key(metric, labels)
        @lock.synchronize { @counters[k] || 0.0 }
      end

      def get_gauge_value(metric, labels = nil)
        k = counter_key(metric, labels)
        @lock.synchronize { @gauges[k] || 0.0 }
      end

      def snapshot
        @lock.synchronize do
          counters = @counters.map do |(name, label_pairs), v|
            { 'name' => name, 'labels' => label_pairs.to_h, 'value' => v }
          end.sort_by { |r| [r['name'], r['labels'].to_json] }

          gauges = @gauges.map do |(name, label_pairs), v|
            { 'name' => name, 'labels' => label_pairs.to_h, 'value' => v }
          end.sort_by { |r| [r['name'], r['labels'].to_json] }

          { 'counters' => counters, 'gauges' => gauges }
        end
      end
    end
  end
end
