require 'bcrypt'

module SIEM
  class Admin < Sequel::Model
    plugin :timestamps, update_on_create: true

    attr_reader :id, :username

    def initialize(id:, username:)
      @id = id
      @username = username
    end

    def before_create
      self.password_hash = BCrypt::Password.create(password) if password
      super
    end

    def self.authenticate(username, password)
      admin = where(username: username).first
      return nil unless admin

      stored_hash = BCrypt::Password.new(admin.password_hash)
      stored_hash == password ? admin : nil
    end

    def self.create(username, password)
      password_hash = BCrypt::Password.create(password)
      DB[:admins].insert(
        username: username,
        password_hash: password_hash,
        created_at: Time.now,
        updated_at: Time.now
      )
    end

    def self.find_by_id(id)
      admin = DB[:admins].where(id: id).first
      return nil unless admin

      new(id: admin[:id], username: admin[:username])
    end

    def update_password(new_password)
      self.password_hash = BCrypt::Password.create(new_password)
      save
    end

    attr_accessor :password

    def to_hash
      {
        id: @id,
        username: @username
      }
    end
  end
end