# frozen_string_literal: true

require 'rake'

namespace :db do
  desc 'Executa migrações Sequel em settings/db/migrations'
  task :migrate do
    require_relative 'server'
    Sequel.extension :migration
    Sequel::Migrator.run(DB, File.expand_path('settings/db/migrations', __dir__))
    puts 'Migrações aplicadas.'
  end
end
