require 'bcrypt'

module SIEM
  class Admin
    DS = DB[:admins]

    attr_reader :id, :username

    def initialize(id:, username:)
      @id = id
      @username = username
    end

    def self.authenticate(username, password)
      row = DS.first(username: username)
      return nil unless row

      r = row.is_a?(Hash) ? row : row.to_hash
      stored_hash = BCrypt::Password.new(r[:password_hash].to_s)
      stored_hash == password ? new(id: r[:id], username: r[:username]) : nil
    end

    def self.create(username, password)
      password_hash = BCrypt::Password.create(password).to_s
      now = Time.now

      id = DS.insert(
        username: username,
        password_hash: password_hash,
        created_at: now,
        updated_at: now
      )
      id ||= DS.max(:id)

      new(id: id, username: username)
    end

    def self.find_by_id(id)
      row = DS[id: id.to_i]
      return nil unless row

      r = row.is_a?(Hash) ? row : row.to_hash
      new(id: r[:id], username: r[:username])
    end

    def update_password(new_password)
      password_hash = BCrypt::Password.create(new_password).to_s
      DS.where(id: @id).update(password_hash: password_hash, updated_at: Time.now)
    end

    def to_hash
      {
        id: @id,
        username: @username
      }
    end
  end
end
