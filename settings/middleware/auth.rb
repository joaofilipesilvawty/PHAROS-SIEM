module SIEM
  class Auth
    def initialize(app)
      @app = app
    end

    def call(env)
      request = Rack::Request.new(env)

      # Rotas públicas que não precisam de autenticação
      public_routes = ['/login', '/auth/login', '/css', '/js', '/images']
      return @app.call(env) if public_routes.any? { |route| request.path.start_with?(route) }

      # Verificar se o usuário está autenticado
      session = request.session
      if session[:admin_id]
        @app.call(env)
      else
        [302, { 'Location' => '/login', 'Content-Type' => 'text/html' }, []]
      end
    end
  end
end