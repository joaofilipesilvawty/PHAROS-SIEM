module SIEM
  module SessionStore
    INDEX = 'sessions'.freeze

    def self.create(session_id:, admin_id:, created_at:, expires_at:)
      ES.index(
        index: INDEX,
        id: session_id.to_s,
        body: {
          id: session_id.to_s,
          admin_id: admin_id.to_s,
          created_at: created_at.iso8601,
          expires_at: expires_at.iso8601
        }
      )
    end

    def self.delete(session_id)
      ES.delete(index: INDEX, id: session_id.to_s)
    rescue StandardError
      nil
    end

    def self.find_valid(session_id)
      doc = ES.get(index: INDEX, id: session_id.to_s)
      return nil unless doc && doc['found']

      src = doc['_source'] || {}
      expires = Time.parse(src['expires_at'].to_s)
      return nil if expires < Time.now

      src
    rescue StandardError
      nil
    end
  end
end
