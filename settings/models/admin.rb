module SIEM
  class Admin
    attr_reader :id, :username

    def initialize(id:, username:)
      @id = id
      @username = username
    end

    def self.authenticate(username, password)
      # TODO: Implementar autenticação segura com bcrypt
      return nil unless username == 'admin' && password == 'joaofilipegsilva'
      new(id: 1, username: username)
    end

    def self.find_by_id(id)
      return nil unless id == 1
      new(id: id, username: 'admin')
    end
  end
end