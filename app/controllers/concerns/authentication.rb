module Authentication
  extend ActiveSupport::Concern

  ACCESS_TOKEN_EXPIRY = 15.minutes
  REFRESH_TOKEN_EXPIRY = 7.days
  REFRESH_TOKEN_COOKIE = :refresh_token # legacy, не используется

  included do
    before_action :authenticate
  end

  class_methods do
    def allow_unauthenticated_access(**options)
      skip_before_action :authenticate, options
    end
  end

  def encode_access_token(payload)
    encode_token(payload, ACCESS_TOKEN_EXPIRY, "access")
  end

  def encode_refresh_token(payload)
    encode_token(payload, REFRESH_TOKEN_EXPIRY, "refresh")
  end

  def decode(token, expected_purpose = nil)
    raise JWT::DecodeError, "Token is missing" if token.blank?
    decoded_payload = JWT.decode(
      token,
      jwt_secret,
      true,
      { algorithm: "HS256" }
    ).first
    if expected_purpose && decoded_payload["purpose"] != expected_purpose
      raise JWT::DecodeError, "Invalid token purpose"
    end
    decoded_payload
  end

  def decode_access_token_from_header
    token = get_token_from_header
    decode(token, "access")
  end

private
  def encode_token(payload, expiry, purpose)
    now = Time.now.to_i
    token_payload = {
      data: {
        id: payload.id
      },
      exp: now + expiry.to_i,
      iat: now,
      iss: "rails_jwt_api",
      aud: "rails_jwt_client",
      sub: payload.id.to_s,
      jti: SecureRandom.uuid,
      nbf: now,
      purpose: purpose
    }
    JWT.encode(
      token_payload,
      jwt_secret,
      "HS256",
      { typ: "JWT", alg: "HS256" }
    )
  end

  def jwt_secret
    ENV["JWT_SECRET"] || Rails.application.credentials.jwt_secret
  end

  def get_token_from_header
    auth_header = request.headers["Authorization"]
    return nil unless auth_header&.start_with?("Bearer ")
    auth_header.split(" ").last
  end

  def current_user
    @current_user ||= find_user_from_access_token
  end

  def find_user_from_access_token
    decoded = decode_access_token_from_header
    return nil unless decoded && decoded.dig("data", "id")
    User.find_by(id: decoded.dig("data", "id"))
  rescue ActiveRecord::RecordNotFound
    nil
  end

  def authenticate
    unless current_user
      render json: { error: "unauthorized", error_description: "User not found or invalid access token" }, status: :unauthorized
      nil
    end
  rescue JWT::ExpiredSignature
    render json: { error: "token_expired", error_description: "Access token has expired" }, status: :unauthorized
    nil
  rescue JWT::DecodeError => e
    render json: { error: "invalid_token", error_description: "Access token is invalid: #{e.message}" }, status: :unauthorized
    nil
  end
end
