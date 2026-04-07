require 'yaml'
require 'fileutils'
require 'logger'

module OPSMON
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
      log_file = File.join(Dir.pwd, 'log', 'opsmon.log')
      logger = Logger.new(log_file, 5, 10 * 1024 * 1024) # 5 files, 10MB each
      logger.level = Logger.const_get(ENV['LOG_LEVEL']&.upcase || 'INFO')
      OPSMON.logger = logger
    end

    def self.load_configuration
      config_file = File.expand_path('../settings.yml', __dir__)
      raise "Ficheiro de config em falta: #{config_file}" unless File.file?(config_file)

      raw = YAML.safe_load(File.read(config_file, encoding: 'UTF-8'), aliases: true)
      OPSMON.setup_yaml = merge_settings_env(raw)
    end

    # Sobrepõe o YAML com ENV de forma explícita (sem ERB), evitando execução de código em templates.
    def self.merge_settings_env(cfg)
      return cfg unless cfg.is_a?(Hash)

      if (db = cfg['database']).is_a?(Hash)
        db['host'] = ENV.fetch('ORACLE_HOST', db['host'])
        db['port'] = ENV.fetch('ORACLE_PORT', db['port']).to_s
        db['service_name'] = ENV.fetch('ORACLE_SERVICE_NAME', db['service_name'])
        db['username'] = ENV.fetch('ORACLE_USERNAME', db['username'])
        db['password'] = ENV.fetch('ORACLE_PASSWORD', db['password'])
      end

      if (srv = cfg['server']).is_a?(Hash)
        port = ENV['PORT'] || srv['port']
        srv['port'] = port.nil? ? 4567 : port.to_i
        srv['environment'] = ENV.fetch('RACK_ENV', srv['environment'])
        srv['session_secret'] = ENV.fetch('SESSION_SECRET', srv['session_secret'])
      end

      if (log = cfg['logging']).is_a?(Hash)
        log['level'] = ENV.fetch('LOG_LEVEL', log['level'])
      end

      cfg
    end

    def self.setup_database
      require 'sequel'
      require 'java'
      require_relative '../../lib/ojdbc8-19.26.0.0.jar'

      db_config = OPSMON.setup_yaml['database']
      connection_string = "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=#{db_config['host']})(PORT=#{db_config['port']}))(CONNECT_DATA=(SERVICE_NAME=#{db_config['service_name']})))"

      db = Sequel.connect(
        adapter: db_config['adapter'],
        driver: db_config['driver'],
        url: connection_string,
        user: db_config['username'],
        password: db_config['password']
      )
      Object.const_set(:DB, db)

      # Create schema if it doesn't exist
      begin
        db.execute("CREATE USER #{db_config['username']} IDENTIFIED BY #{db_config['password']}")
        db.execute("GRANT CONNECT, RESOURCE TO #{db_config['username']}")
      rescue => e
        OPSMON.logger.warn("Database user already exists: #{e.message}")
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

      OPSMON.logger.info("Created default admin user with password: #{password}")
    end
  end
end