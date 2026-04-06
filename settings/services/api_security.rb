require 'jwt'

module OPSMON
  class APISecurity
    def self.secure_endpoint(endpoint)
      {
        rate_limiting: setup_rate_limiting,
        authentication: setup_authentication,
        authorization: setup_authorization,
        encryption: setup_encryption,
        logging: setup_logging
      }
    end

    def self.setup_rate_limiting
      {
        enabled: true,
        max_requests: (ENV['API_RATE_LIMIT_MAX_REQUESTS'] || 100).to_i,
        window: (ENV['API_RATE_LIMIT_WINDOW'] || 60).to_i
      }
    end

    def self.setup_authentication
      {
        enabled: true,
        methods: ['jwt', 'api_key'],
        jwt_secret: ENV['API_JWT_SECRET'],
        api_key_header: 'X-API-Key'
      }
    end

    def self.setup_authorization
      {
        enabled: true,
        roles: ['admin', 'user', 'service'],
        permissions: {
          admin: ['read', 'write', 'delete'],
          user: ['read'],
          service: ['read', 'write']
        }
      }
    end

    def self.setup_encryption
      {
        enabled: true,
        algorithm: 'AES-256-GCM',
        key_rotation: ENV['API_ENCRYPTION_KEY_ROTATION'] || 30
      }
    end

    def self.setup_logging
      {
        enabled: true,
        level: ENV['API_LOG_LEVEL'] || 'info',
        format: 'json',
        fields: ['timestamp', 'method', 'path', 'status', 'duration', 'ip', 'user_id']
      }
    end

    def self.validate_request(request)
      return false unless validate_rate_limit(request)
      return false unless validate_authentication(request)
      return false unless validate_authorization(request)
      true
    end

    private

    def self.validate_rate_limit(request)
      return true unless $redis

      client_ip = request.ip
      key = "rate_limit:#{client_ip}"
      cfg = setup_rate_limiting

      current = $redis.get(key).to_i
      return false if current >= cfg[:max_requests]

      $redis.incr(key)
      $redis.expire(key, cfg[:window])
      true
    rescue StandardError
      true
    end

    def self.validate_authentication(request)
      ingest = ENV['INGEST_API_KEY'].to_s
      if !ingest.empty?
        header_key = request.env['HTTP_X_API_KEY'] || request.env['HTTP_X_INGEST_KEY']
        return true if header_key == ingest
      end

      auth_header = request.env['HTTP_AUTHORIZATION']
      return false unless auth_header

      if auth_header.start_with?('Bearer ')
        validate_jwt(auth_header.split(' ', 2).last)
      elsif auth_header.start_with?('ApiKey ')
        validate_api_key(auth_header.split(' ', 2).last)
      else
        false
      end
    end

    def self.validate_authorization(request)
      user = get_user_from_request(request)
      return false unless user

      required_permission = get_required_permission(request)
      get_user_permissions(user).include?(required_permission)
    end

    def self.validate_jwt(token)
      secret = setup_authentication[:jwt_secret]
      return false if secret.nil? || secret.to_s.empty?

      JWT.decode(token.to_s, secret, true, algorithm: 'HS256')
      true
    rescue JWT::DecodeError
      false
    end

    def self.validate_api_key(key)
      return false unless $redis

      !$redis.get("api_key:#{key}").nil?
    rescue StandardError
      false
    end

    def self.get_user_from_request(request)
      ingest = ENV['INGEST_API_KEY'].to_s
      if !ingest.empty?
        header_key = request.env['HTTP_X_API_KEY'] || request.env['HTTP_X_INGEST_KEY']
        return 'ingest' if header_key == ingest
      end

      auth_header = request.env['HTTP_AUTHORIZATION']
      return nil unless auth_header

      secret = setup_authentication[:jwt_secret]

      if auth_header.start_with?('Bearer ') && secret && !secret.to_s.empty?
        payload = JWT.decode(auth_header.split(' ', 2).last, secret, true, algorithm: 'HS256').first
        payload['user_id'] || payload['sub']
      elsif auth_header.start_with?('ApiKey ') && $redis
        k = auth_header.split(' ', 2).last
        $redis.get("api_key_user:#{k}")
      end
    rescue JWT::DecodeError
      nil
    end

    def self.get_required_permission(request)
      case request.request_method
      when 'GET'
        'read'
      when 'POST', 'PUT', 'PATCH'
        'write'
      when 'DELETE'
        'delete'
      else
        'read'
      end
    end

    def self.get_user_permissions(user)
      perms = setup_authorization[:permissions]
      return perms[:admin] if user.to_s == 'ingest'

      return perms[:admin] unless $redis

      role = $redis.get("user_role:#{user}")
      return perms[:admin] if role.nil? || role.to_s.empty?

      perms[role.to_sym] || []
    rescue StandardError
      setup_authorization[:permissions][:admin]
    end
  end
end
