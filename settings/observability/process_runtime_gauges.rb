# frozen_string_literal: true

# Gauges de processo — alinhado a process_runtime_gauges.py (CPU + memória).

module OPSMON
  module ProcessRuntimeGauges
    module_function

    def refresh
      cpu = process_cpu_percent
      rss = process_memory_rss_bytes
      OPSMON::InternalMetrics.set_gauge('process_cpu_percent', cpu, {}) if cpu
      OPSMON::InternalMetrics.set_gauge('process_memory_rss_bytes', rss, {}) if rss
    end

    def process_cpu_percent
      if defined?(JRUBY_VERSION) && defined?(Java)
        begin
          bean = Java::JavaLangManagement::ManagementFactory.getOperatingSystemMXBean
          return nil unless bean.respond_to?(:processCpuLoad)

          v = bean.processCpuLoad
          return nil if v.nil? || v.negative?

          (v.to_f * 100.0).round(2)
        rescue StandardError
          nil
        end
      else
        # MRI: sem dependência extra, não definimos CPU de processo
        nil
      end
    end

    def process_memory_rss_bytes
      if defined?(JRUBY_VERSION) && defined?(Java)
        begin
          rt = Java::JavaLang::Runtime.getRuntime
          (rt.totalMemory - rt.freeMemory).to_i
        rescue StandardError
          nil
        end
      else
        begin
          # Linux: VmRSS em /proc/self/status (bytes aproximados)
          if File.readable?('/proc/self/status')
            File.read('/proc/self/status').each_line do |line|
              next unless line.start_with?('VmRSS:')

              kb = line.split[1].to_i
              return kb * 1024
            end
          end
        rescue StandardError
          nil
        end
        nil
      end
    end
  end
end
