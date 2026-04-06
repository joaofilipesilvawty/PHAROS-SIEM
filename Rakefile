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

namespace :admin do
  desc 'Define ou repõe a palavra-passe (ADMIN_USER=admin ADMIN_PASSWORD=segredo bundle exec rake admin:password)'
  task :password do
    require_relative 'server'
    user = ENV['ADMIN_USER'] || 'admin'
    pwd = ENV['ADMIN_PASSWORD'].to_s
    if pwd.empty?
      warn 'Define ADMIN_PASSWORD no ambiente (ex.: ADMIN_PASSWORD=minhasenha bundle exec rake admin:password)'
      exit 1
    end
    SIEM::Admin.set_password!(user, pwd)
    puts "Password atualizada para o utilizador #{user.inspect}."
  end
end
