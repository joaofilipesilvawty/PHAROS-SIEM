# frozen_string_literal: true
require 'time'

module OPSMON
  module FeatureFlags
    @lock = Mutex.new
    @flags = {}

    class << self
      def now_iso
        Time.now.utc.iso8601
      end

      def normalize_flag(input)
        h = input.is_a?(Hash) ? input : {}
        {
          'name' => h['name'].to_s.strip,
          'description' => h.fetch('description', '').to_s,
          'status' => h.fetch('status', 'disabled').to_s,
          'enabled' => !!h.fetch('enabled', false),
          'rollout_percentage' => [[h.fetch('rollout_percentage', 0).to_i, 0].max, 100].min,
          'environments' => Array(h['environments']).map(&:to_s),
          'tenants' => Array(h['tenants']).map(&:to_s),
          'users' => Array(h['users']).map(&:to_s),
          'roles' => Array(h['roles']).map(&:to_s),
          'metadata' => (h['metadata'].is_a?(Hash) ? h['metadata'] : {}),
          'created_at' => h['created_at'] || now_iso,
          'updated_at' => now_iso
        }
      end

      def all
        @lock.synchronize { @flags.values.map(&:dup).sort_by { |f| f['name'] } }
      end

      def get(name)
        key = name.to_s
        @lock.synchronize { @flags[key]&.dup }
      end

      def create(payload)
        flag = normalize_flag(payload)
        raise ArgumentError, 'name é obrigatório' if flag['name'].empty?

        @lock.synchronize do
          raise ArgumentError, 'feature flag já existe' if @flags.key?(flag['name'])

          @flags[flag['name']] = flag
          flag.dup
        end
      end

      def update(name, payload)
        key = name.to_s
        @lock.synchronize do
          current = @flags[key]
          return nil unless current

          patch = payload.is_a?(Hash) ? payload : {}
          current['description'] = patch['description'].to_s if patch.key?('description')
          current['status'] = patch['status'].to_s if patch.key?('status')
          current['enabled'] = !!patch['enabled'] if patch.key?('enabled')
          if patch.key?('rollout_percentage')
            current['rollout_percentage'] = [[patch['rollout_percentage'].to_i, 0].max, 100].min
          end
          current['environments'] = Array(patch['environments']).map(&:to_s) if patch.key?('environments')
          current['tenants'] = Array(patch['tenants']).map(&:to_s) if patch.key?('tenants')
          current['users'] = Array(patch['users']).map(&:to_s) if patch.key?('users')
          current['roles'] = Array(patch['roles']).map(&:to_s) if patch.key?('roles')
          if patch.key?('metadata')
            current['metadata'] = patch['metadata'].is_a?(Hash) ? patch['metadata'] : current['metadata']
          end
          current['updated_at'] = now_iso
          current.dup
        end
      end

      def set_enabled(name, enabled)
        update(name, { 'enabled' => enabled, 'status' => (enabled ? 'enabled' : 'disabled') })
      end

      def set_rollout(name, percentage)
        update(name, { 'rollout_percentage' => percentage })
      end

      def deprecate(name)
        update(name, { 'enabled' => false, 'status' => 'deprecated' })
      end
    end
  end
end
