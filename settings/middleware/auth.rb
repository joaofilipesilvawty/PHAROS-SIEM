module OPSMON
  class Auth
    def initialize(app)
      @app = app
    end

    def call(env)
      request = Rack::Request.new(env)

      # Rotas públicas que não precisam de autenticação
      public_routes = ['/login', '/auth/login', '/css', '/js', '/images']
      return @app.call(env) if public_routes.any? { |route| request.path.start_with?(route) }
      # Ficheiros estáticos em /css, /js, /images e na raiz do public (ex. /favicon.ico)
      return @app.call(env) if request.path.match?(%r{\A/[\w.-]+\.(css|js|map|ico|png|jpe?g|gif|svg|woff2?)\z}i)

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