require 'bcrypt'

module SIEM
  class Admin
    DS = DB[:admins]

    attr_reader :id, :username

    def initialize(id:, username:)
      @id = id
      @username = username
    end

    # Oracle/JDBC devolve chaves em maiúsculas ou misto; normaliza para símbolos em minúsculas.
    def self.normalize_row(row)
      return nil unless row

      h = row.is_a?(Hash) ? row : row.to_hash
      h.transform_keys { |k| k.to_s.downcase.to_sym }
    end

    def self.authenticate(username, password)
      u = username.to_s.strip
      pw = password.to_s
      return nil if u.empty? || pw.empty?

      row = begin
        DS.where(Sequel.function(:upper, :username) => u.upcase).first
      rescue StandardError => e
        warn "[SIEM] Admin.authenticate: lookup UPPER(username) falhou (#{e.class}: #{e.message}); a usar varredura."
        nil
      end
      row ||= DS.first(username: u)
      row ||= DS.first(username: u.downcase)
      row ||= DS.first(username: u.capitalize)
      row ||= DS.all.find { |raw| (r = normalize_row(raw)) && r[:username].to_s.downcase == u.downcase }
      return nil unless row

      r = normalize_row(row)
      hash_str = r[:password_hash].to_s
      return nil if hash_str.empty?

      begin
        stored_hash = BCrypt::Password.new(hash_str)
      rescue BCrypt::Errors::InvalidHash => e
        warn "[SIEM] Admin.authenticate: hash BCrypt inválido para #{u.inspect}: #{e.message}"
        return nil
      end

      return nil unless stored_hash == pw

      new(id: r[:id].to_i, username: r[:username].to_s)
    end

    def self.create(username, password)
      password_hash = BCrypt::Password.create(password).to_s
      now = Time.now

      id = DS.insert(
        username: username.to_s.strip,
        password_hash: password_hash,
        created_at: now,
        updated_at: now
      )
      id ||= DS.max(:id)

      new(id: id.to_i, username: username.to_s.strip)
    end

    def self.find_by_id(id)
      row = DS[id: id.to_i]
      return nil unless row

      r = normalize_row(row)
      new(id: r[:id].to_i, username: r[:username].to_s)
    end

    def update_password(new_password)
      password_hash = BCrypt::Password.create(new_password).to_s
      DS.where(id: @id).update(password_hash: password_hash, updated_at: Time.now)
    end

    # Cria ou atualiza password (útil com rake admin:password).
    def self.set_password!(username, plain_password)
      u = username.to_s.strip
      raise ArgumentError, 'username vazio' if u.empty?
      raise ArgumentError, 'password vazio' if plain_password.to_s.empty?

      row = begin
        DS.where(Sequel.function(:upper, :username) => u.upcase).first
      rescue StandardError
        nil
      end
      row ||= DS.first(username: u)
      row ||= DS.all.find { |raw| (r = normalize_row(raw)) && r[:username].to_s.downcase == u.downcase }

      if row
        r = normalize_row(row)
        new(id: r[:id].to_i, username: r[:username].to_s).update_password(plain_password)
      else
        create(u, plain_password)
      end
    end

    def to_hash
      {
        id: @id,
        username: @username
      }
    end
  end
end
