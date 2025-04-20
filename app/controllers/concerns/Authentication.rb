module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :authenticate
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :authenticate, options
    end
  end

  def encode(payload)
    now = Time.now.to_i
    JWT.encode(
      {
        data: {
          id: payload.id,
          email_address: payload.email_address
        },
        exp: now + 3.minutes.to_i,
        iat: now,
        iss: "rails_jwt_api",
        aud: "rails_jwt_client",
        sub: "User",
        jti: SecureRandom.uuid,
        nbf: now + 1.second.to_i
      },
      jwt_secret,
      "HS256",
      {
        typ: "JWT",
        alg: "HS256"
      }
    )
  end

  def decode
    token = get_token
    begin
      JWT.decode(token, jwt_secret, true, { algorithm: "HS256" })
    rescue JWT::DecodeError => e
      render json: { error: "Invalid token: #{e.message}" }, status: :unauthorized
    end
  end

private

  def jwt_secret
    ENV["JWT_SECRET"] || Rails.application.credentials.jwt_secret
  end

  def get_token
    request.headers["Authorization"].split(" ").last
  end

  def current_user
    decoded = decode
    decoded.first["data"].with_indifferent_access
  end

  def authenticate
    begin
      if current_user
        current_user
      else
        render json: { error: "Unauthorized" }, status: :unauthorized
      end
    rescue JWT::ExpiredSignature
      render json: { error: "Token has expired" }, status: :unauthorized
    end
  end
end
