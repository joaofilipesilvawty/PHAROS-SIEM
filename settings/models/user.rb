module SIEM
  class User < Sequel::Model
    plugin :validation_helpers
    plugin :timestamps

    def validate
      super
      validates_presence [:vat_number, :password_hash]
      validates_unique :vat_number
      validates_format /^[A-Z]{2}[0-9]{9}$/, :vat_number
    end

    def before_create
      self.api_key = SecureRandom.hex(32) if self.api_key.nil?
      super
    end

    def to_hash
      {
        id: id,
        vat_number: vat_number,
        name: name,
        company_name: company_name,
        roles: roles.map(&:to_hash),
        created_at: created_at,
        updated_at: updated_at
      }
    end

    def has_role?(role_name)
      roles.any? { |role| role.name == role_name }
    end

    def is_admin?
      has_role?('admin')
    end

    def is_security_analyst?
      has_role?('security_analyst')
    end

    def is_auditor?
      has_role?('auditor')
    end
  end
end
