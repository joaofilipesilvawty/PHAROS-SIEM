require 'sequel'
require 'bcrypt'
require 'dotenv'
require 'java'
require_relative 'lib/ojdbc8-19.26.0.0.jar'
Dotenv.load

# Database connection
DB = Sequel.connect(
  adapter: 'jdbc',
  driver: 'oracle.jdbc.driver.OracleDriver',
  url: "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=#{ENV['ORACLE_HOST']})(PORT=#{ENV['ORACLE_PORT'] || '1521'}))(CONNECT_DATA=(SERVICE_NAME=#{ENV['ORACLE_SERVICE_NAME'] || 'orclpdb1'})))",
  user: ENV['ORACLE_USERNAME'],
  password: ENV['ORACLE_PASSWORD']
)

# Admin model
module SIEM
  class Admin < Sequel::Model
    def self.create_or_update(username, password)
      password_hash = BCrypt::Password.create(password)
      existing_admin = DB[:admins].where(username: username).first

      if existing_admin
        DB[:admins].where(id: existing_admin[:id]).update(
          password_hash: password_hash,
          updated_at: Time.now
        )
        :updated
      else
        DB[:admins].insert(
          username: username,
          password_hash: password_hash,
          created_at: Time.now,
          updated_at: Time.now
        )
        :created
      end
    end
  end
end

namespace :admin do
  desc 'Create or update admin user'
  task :create do
    username = 'admin'
    password = 'joaofilipegsilva'

    begin
      result = SIEM::Admin.create_or_update(username, password)
      action = result == :created ? "created" : "updated"
      puts "Admin user #{action} successfully!"
      puts "Username: #{username}"
      puts "Password: #{password}"
    rescue => e
      puts "Error managing admin user: #{e.message}"
    end
  end
end