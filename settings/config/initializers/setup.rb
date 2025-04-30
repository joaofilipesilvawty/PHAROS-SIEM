require 'yaml'
require 'erb'
require 'fileutils'
require 'logger'

module SIEM
  class Setup
    def self.initialize!
      setup_directories
      setup_logger
      load_configuration
      setup_database
      create_admin_user
    end

    private

    def self.setup_directories
      %w[log tmp settings/db settings/config/environments].each do |dir|
        FileUtils.mkdir_p(dir)
      end
    end

    def self.setup_logger
      log_file = File.join(Dir.pwd, 'log', 'siem.log')
      logger = Logger.new(log_file, 5, 10 * 1024 * 1024) # 5 files, 10MB each
      logger.level = Logger.const_get(ENV['LOG_LEVEL']&.upcase || 'INFO')
      SIEM.logger = logger
    end

    def self.load_configuration
      config_file = File.join(Dir.pwd, 'config', 'settings.yml')
      config_content = ERB.new(File.read(config_file)).result
      SIEM.config = YAML.safe_load(config_content, aliases: true)
    end

    def self.setup_database
      require 'sequel'
      require 'java'
      require_relative '../../lib/ojdbc8-19.26.0.0.jar'

      db_config = SIEM.config['database']
      connection_string = "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=#{db_config['host']})(PORT=#{db_config['port']}))(CONNECT_DATA=(SERVICE_NAME=#{db_config['service_name']})))"

      DB = Sequel.connect(
        adapter: db_config['adapter'],
        driver: db_config['driver'],
        url: connection_string,
        user: db_config['username'],
        password: db_config['password']
      )

      # Create schema if it doesn't exist
      begin
        DB.execute("CREATE USER #{db_config['username']} IDENTIFIED BY #{db_config['password']}")
        DB.execute("GRANT CONNECT, RESOURCE TO #{db_config['username']}")
      rescue => e
        SIEM.logger.warn("Database user already exists: #{e.message}")
      end

      # Create tables
      require_relative '../../settings/models/security_log'
      require_relative '../../settings/models/alert'
      require_relative '../../settings/models/metric'
      require_relative '../../settings/models/admin'
    end

    def self.create_admin_user
      return if DB[:admins].count > 0

      password = ENV['ADMIN_PASSWORD'] || SecureRandom.hex(16)
      password_hash = BCrypt::Password.create(password)

      DB[:admins].insert(
        username: 'admin',
        password_hash: password_hash,
        created_at: Time.now,
        updated_at: Time.now
      )

      SIEM.logger.info("Created default admin user with password: #{password}")
    end
  end
end