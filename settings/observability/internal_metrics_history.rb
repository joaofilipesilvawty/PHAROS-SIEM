# frozen_string_literal: true

# Histórico para gráficos — alinhado a internal_metrics_history.py (ring buffer + JSONL).

require 'json'
require 'fileutils'
require 'pathname'

module OPSMON
  module InternalMetricsHistory
    MAX_POINTS = 200
    MAX_NAMES = 8
    MAX_FILE_BYTES = 512 * 1024

    @lock = Mutex.new
    @points = []
    @loaded = false

    class << self
      def history_path
        base = ENV['OPSMON_CHART_HISTORY_DIR'] || File.join(Dir.pwd, 'log')
        File.join(base, 'opsmon_chart_history.jsonl')
      end

      def agg_counter_by_name(counters)
        acc = {}
        Array(counters).each do |r|
          name = r['name'].to_s
          next if name.empty?

          acc[name] = acc.fetch(name, 0.0) + r['value'].to_f
        end
        acc.sort_by { |_k, v| -v.abs }.first(MAX_NAMES).to_h
      end

      def agg_gauge_by_name(gauges)
        acc = {}
        Array(gauges).each do |r|
          name = r['name'].to_s
          next if name.empty?

          acc[name] = r['value'].to_f
        end
        acc.sort_by { |_k, v| -v.abs }.first(MAX_NAMES).to_h
      end

      INFRA_GAUGE_NAMES = %w[process_cpu_percent process_memory_rss_bytes].freeze

      def extract_infra_gauges(gauges)
        out = INFRA_GAUGE_NAMES.to_h { |n| [n, nil] }
        Array(gauges).each do |r|
          name = r['name'].to_s
          next unless out.key?(name)

          out[name] = r['value'].to_f
        end
        out
      end

      def load_from_disk
        return if @loaded

        @lock.synchronize do
          return if @loaded

          path = history_path
          if File.file?(path)
            begin
              File.readlines(path, chomp: true).each do |line|
                line = line.strip
                next if line.empty?

                begin
                  @points << JSON.parse(line)
                rescue JSON::ParserError
                  next
                end
              end
              @points.shift while @points.size > MAX_POINTS
            rescue StandardError
              # ignore
            end
          end
          @loaded = true
        end
      end

      def append_disk(point)
        path = history_path
        FileUtils.mkdir_p(File.dirname(path))
        File.open(path, 'a', encoding: 'UTF-8') { |f| f.puts(JSON.generate(point)) }
        trim_file_if_huge
      rescue StandardError
        # ignore
      end

      def trim_file_if_huge
        path = history_path
        return unless File.file?(path)
        return if File.size(path) <= MAX_FILE_BYTES

        lines = File.readlines(path, chomp: true)
        keep = lines.last(MAX_POINTS)
        File.write(path, keep.join("\n") + (keep.empty? ? '' : "\n"), encoding: 'UTF-8')
      rescue StandardError
        # ignore
      end

      def record_runtime_sample(runtime_metrics)
        load_from_disk
        counters = runtime_metrics['counters'] || []
        gauges = runtime_metrics['gauges'] || []
        sum_c = counters.sum { |r| r['value'].to_f }
        sum_g = gauges.sum { |r| r['value'].to_f }
        n_g = gauges.size
        avg_g = n_g.positive? ? sum_g / n_g : 0.0

        point = {
          'ts' => Time.now.to_f,
          'counter_sum' => sum_c,
          'gauge_avg' => avg_g,
          'n_counters' => counters.size,
          'n_gauges' => n_g,
          'counter_by_name' => agg_counter_by_name(counters),
          'gauge_by_name' => agg_gauge_by_name(gauges),
          'infra_gauges' => extract_infra_gauges(gauges)
        }

        @lock.synchronize do
          @points << point
          @points.shift while @points.size > MAX_POINTS
        end
        append_disk(point)
      end

      def chart_series
        load_from_disk
        path = history_path
        rel = begin
          Pathname.new(path).relative_path_from(Pathname.new(Dir.pwd)).to_s
        rescue ArgumentError
          path
        end

        @lock.synchronize do
          {
            'points' => @points.dup,
            'meta' => {
              'max_points' => MAX_POINTS,
              'max_series_per_chart' => MAX_NAMES,
              'persistence_path' => rel
            }
          }
        end
      end
    end
  end
end
