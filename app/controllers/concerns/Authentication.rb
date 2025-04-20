module Authentication
  extend ActiveSupport::Concern

  included do
    before_action :authenticate
  end

  class_methods do
    # Allows skipping the authenticate before_action for specific controller actions.
    def allow_unauthenticated_access(**options)
      skip_before_action :authenticate, options
    end
  end

  # Encodes the user payload into a JWT.
  def encode(payload)
    now = Time.now.to_i
    JWT.encode(
      {
        data: { # User specific data
          id: payload.id,
          email_address: payload.email_address
        },
        # Standard JWT claims
        exp: now + 1.minutes.to_i, # Expiration Time
        iat: now,                  # Issued At
        iss: "rails_jwt_api",      # Issuer
        aud: "rails_jwt_client",   # Audience
        sub: "User",               # Subject
        jti: SecureRandom.uuid,    # JWT ID
        nbf: now + 1.second.to_i   # Not Before
      },
      jwt_secret,                # The secret key
      "HS256",                   # The signing algorithm
      {
        # Optional headers
        typ: "JWT",
        alg: "HS256"
      }
    )
  end

  # Decodes the JWT token from the Authorization header.
  # Raises JWT::DecodeError if the token is missing or invalid.
  # Raises JWT::ExpiredSignature if the token has expired.
  def decode
    token = get_token
    # Raise an error if the token is missing from the header
    raise JWT::DecodeError, "Authorization token is missing" if token.blank?

    # JWT.decode will raise an error if the token is invalid (e.g., bad signature, expired)
    # Errors will be caught in the authenticate method.
    JWT.decode(token, jwt_secret, true, { algorithm: "HS256" }).first # Returns the payload
  end

private

  # Retrieves the JWT secret key from environment variables or Rails credentials.
  def jwt_secret
    ENV["JWT_SECRET"] || Rails.application.credentials.jwt_secret
  end

  # Extracts the token string from the 'Authorization: Bearer <token>' header.
  def get_token
    auth_header = request.headers["Authorization"]
    # Return nil if the header is missing or doesn't start with 'Bearer '
    return nil unless auth_header&.start_with?("Bearer ")
    auth_header.split(" ").last
  end

  # Memoized method to find and return the current authenticated user.
  # Returns the User object or nil if not authenticated or user not found.
  def current_user
    # Return the already found user if available (memoization)
    @current_user ||= find_user_from_token
  end

  # Finds the user based on the ID stored in the decoded JWT payload.
  def find_user_from_token
    decoded = decode # decode will raise errors if token is invalid/expired
    # Return nil if decoding failed or payload doesn't contain the user ID
    return nil unless decoded && decoded.dig("data", "id")

    # Find the user in the database using the ID from the token
    User.find_by(id: decoded.dig("data", "id"))
  rescue ActiveRecord::RecordNotFound
    # Return nil if a user with the ID from the token is not found in the DB
    nil
  end

  # The main authentication method used as a before_action filter.
  # It attempts to set @current_user. If authentication fails (no user,
  # invalid/expired token), it renders an appropriate JSON error response
  # and halts the request chain.
  def authenticate
    # Calling current_user triggers the whole process:
    # get_token -> decode -> find_user_from_token
    unless current_user
      # This block is reached if find_user_from_token returned nil
      # (e.g., user not found in DB after successful token decode).
      # JWT errors (expired, invalid) are caught below.
      render json: { error: "Unauthorized" }, status: :unauthorized
      nil # Halt execution
    end
  rescue JWT::ExpiredSignature
    # Catch expired token error
    render json: { error: "Token has expired" }, status: :unauthorized
    nil # Halt execution
  rescue JWT::DecodeError => e
    # Catch errors from decode (missing token, invalid format/signature, etc.)
    render json: { error: "Invalid token: #{e.message}" }, status: :unauthorized
    nil # Halt execution
  end
end
