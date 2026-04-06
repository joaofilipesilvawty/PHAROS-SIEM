require 'rack/cors'

module OPSMON
  module Middleware
    def self.configure(app)
      app.use Rack::Cors do
        allow do
          origins '*'
          resource '*', headers: :any, methods: [:get, :post, :put, :delete, :options]
        end
      end
    end
  end
end