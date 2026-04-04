module SIEM
  module SessionStore
    DS = DB[:sessions]

    def self.create(session_id:, admin_id:, created_at:, expires_at:)
      DS.insert(
        id: session_id.to_s,
        admin_id: admin_id.to_i,
        created_at: created_at,
        expires_at: expires_at
      )
    end

    def self.delete(session_id)
      DS.where(id: session_id.to_s).delete
    end

    def self.find_valid(session_id)
      row = DS.first(id: session_id.to_s)
      return nil unless row

      r = row.is_a?(Hash) ? row : row.to_hash
      return nil if r[:expires_at].nil? || r[:expires_at] < Time.now
      {
        'id' => r[:id].to_s,
        'admin_id' => r[:admin_id],
        'created_at' => r[:created_at],
        'expires_at' => r[:expires_at]
      }
    end
  end
end
