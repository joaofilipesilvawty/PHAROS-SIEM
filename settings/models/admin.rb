require 'bcrypt'

module SIEM
  class Admin
    attr_reader :id, :username

    def initialize(id:, username:)
      @id = id
      @username = username
    end

    def self.authenticate(username, password)
      response = ES.search(
        index: 'admins',
        body: {
          query: {
            term: { username: username }
          }
        }
      )

      return nil if response['hits']['hits'].empty?

      admin_data = response['hits']['hits'].first['_source']
      stored_hash = BCrypt::Password.new(admin_data['password_hash'])
      stored_hash == password ? new(id: admin_data['id'], username: admin_data['username']) : nil
    end

    def self.create(username, password)
      password_hash = BCrypt::Password.create(password)
      now = Time.now

      response = ES.index(
        index: 'admins',
        body: {
          username: username,
          password_hash: password_hash,
          created_at: now,
          updated_at: now
        }
      )

      new(id: response['_id'], username: username)
    end

    def self.find_by_id(id)
      response = ES.get(
        index: 'admins',
        id: id
      ) rescue nil

      return nil unless response

      new(id: response['_id'], username: response['_source']['username'])
    end

    def update_password(new_password)
      password_hash = BCrypt::Password.create(new_password)
      ES.update(
        index: 'admins',
        id: @id,
        body: {
          doc: {
            password_hash: password_hash,
            updated_at: Time.now
          }
        }
      )
    end

    def to_hash
      {
        id: @id,
        username: @username
      }
    end
  end
end