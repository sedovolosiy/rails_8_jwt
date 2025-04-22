# frozen_string_literal: true

# Gem dependency: Ensure 'jwt' gem is in your Gemfile
# gem 'jwt'

# Module providing JWT-based authentication logic for controllers.
# It uses ActiveSupport::Concern for easy inclusion into controllers.
# Handles encoding/decoding of access and refresh tokens, and provides
# a before_action hook for authenticating requests.
module Authentication
  extend ActiveSupport::Concern

  # --- Custom Error Classes ---
  class AuthenticationError < StandardError; end
  class MissingTokenError < AuthenticationError; end
  class InvalidTokenError < AuthenticationError; end
  class ExpiredTokenError < AuthenticationError; end
  class InvalidTokenPurposeError < InvalidTokenError; end
  class UserNotFoundError < AuthenticationError; end

  # --- Configuration Constants ---
  # Default expiry times (in seconds) - can be overridden by ENV variables.
  DEFAULT_ACCESS_TOKEN_EXPIRY  = 15 * 60 # 15 minutes
  DEFAULT_REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 # 7 days
  ACCESS_TOKEN_EXPIRY  = ENV.fetch("ACCESS_TOKEN_EXPIRY", DEFAULT_ACCESS_TOKEN_EXPIRY).to_i
  REFRESH_TOKEN_EXPIRY = ENV.fetch("REFRESH_TOKEN_EXPIRY", DEFAULT_REFRESH_TOKEN_EXPIRY).to_i

  # JWT Standard Claims Configuration
  JWT_ISSUER  = ENV.fetch("JWT_ISSUER", "rails_jwt_api")    # Identifies the principal that issued the JWT.
  JWT_AUDIENCE = ENV.fetch("JWT_AUDIENCE", "rails_jwt_client") # Identifies the recipients that the JWT is intended for.
  JWT_ALGORITHM = "HS256" # The signing algorithm.

  # JWT Payload Keys (using constants improves maintainability)
  PAYLOAD_DATA_KEY = :data
  PAYLOAD_ID_KEY   = :id
  PAYLOAD_PURPOSE_KEY = :purpose
  PURPOSE_ACCESS  = "access"
  PURPOSE_REFRESH = "refresh"

  # --- Concern Logic ---

  included do
    # Add the authenticate method as a before_action hook to controllers.
    before_action :authenticate
  end

  # --- Class Methods ---

  class_methods do
    # Allows skipping the :authenticate before_action for specific controller actions.
    #
    # @param options [Hash] Options hash passed directly to `skip_before_action`.
    # @example Skip authentication for :index and :show actions
    #   allow_unauthenticated_access only: [:index, :show]
    # @example Skip authentication for all actions except :destroy
    #   allow_unauthenticated_access except: [:destroy]
    def allow_unauthenticated_access(**options)
      skip_before_action :authenticate, options
    end
  end

  # --- Public Instance Methods (available in controllers) ---

  # Encodes a payload into an access token with a standard expiry time.
  #
  # @param payload [#id] The object to encode (e.g., User). Must respond to `#id`.
  # @return [String] The generated JWT access token.
  def encode_access_token(payload)
    encode_token(payload, ACCESS_TOKEN_EXPIRY, PURPOSE_ACCESS)
  end

  # Encodes a payload into a refresh token with a longer expiry time.
  #
  # @param payload [#id] The object to encode (e.g., User). Must respond to `#id`.
  # @return [String] The generated JWT refresh token.
  def encode_refresh_token(payload)
    encode_token(payload, REFRESH_TOKEN_EXPIRY, PURPOSE_REFRESH)
  end

  # Decodes a JWT token, verifies its signature, checks standard claims, and optionally checks its purpose.
  #
  # @param token [String] The JWT token string to decode.
  # @param expected_purpose [String, nil] The expected purpose claim ('access' or 'refresh'). If nil, purpose is not checked.
  # @return [Hash] The decoded payload hash (symbolized keys).
  # @raise [MissingTokenError] If the token is blank.
  # @raise [InvalidTokenError] If the token signature is invalid, format is wrong, or standard claims validation fails.
  # @raise [ExpiredTokenError] If the token has expired (based on 'exp' claim).
  # @raise [InvalidTokenPurposeError] If `expected_purpose` is provided and doesn't match the token's purpose.
  def decode(token, expected_purpose = nil)
    raise MissingTokenError, "Token cannot be blank" if token.blank?

    begin
      # Decode the token using the secret key and specified algorithm.
      # JWT.decode performs verification of:
      # - Signature
      # - Expiration ('exp') claim (raises JWT::ExpiredSignature)
      # - Not Before ('nbf') claim (raises JWT::ImmatureSignature)
      # - Issued At ('iat') claim (raises JWT::InvalidIat)
      # - Issuer ('iss') claim if verify_iss is true
      # - Audience ('aud') claim if verify_aud is true
      # - Subject ('sub') claim if verify_sub is true
      # - JWT ID ('jti') claim if verify_jti is true
      decoded_payload, _header = JWT.decode(
        token,
        jwt_secret,
        true, # Verify signature
        {
          algorithm: JWT_ALGORITHM,
          iss: JWT_ISSUER,
          aud: JWT_AUDIENCE,
          verify_iss: true, # Enforce issuer validation
          verify_aud: true # Enforce audience validation
          # Leeway allows for clock skew between servers (e.g., 5 seconds)
          # leeway: 5,
          # You can add more verification options here if needed (verify_iat, verify_jti etc.)
        }
      )

      # Symbolize keys for consistent access
      payload = decoded_payload.deep_symbolize_keys

      # Check custom purpose claim if required
      if expected_purpose && payload[PAYLOAD_PURPOSE_KEY] != expected_purpose
        raise InvalidTokenPurposeError, "Invalid token purpose: expected '#{expected_purpose}', got '#{payload[PAYLOAD_PURPOSE_KEY]}'"
      end

      payload

    # Map specific JWT gem errors to our custom application errors
    rescue JWT::ExpiredSignature => e
      raise ExpiredTokenError, "Token has expired: #{e.message}"
    rescue JWT::ImmatureSignature, JWT::InvalidIat => e
      raise InvalidTokenError, "Token not yet valid: #{e.message}"
    rescue JWT::InvalidIssuerError, JWT::InvalidAudError => e
      raise InvalidTokenError, "Token validation failed (issuer/audience): #{e.message}"
    rescue JWT::VerificationError => e
      raise InvalidTokenError, "Token signature verification failed: #{e.message}"
    rescue JWT::DecodeError => e # Catch-all for other JWT decoding issues (format, etc.)
      raise InvalidTokenError, "Token is invalid: #{e.message}"
    end
  end

  # Extracts the access token from the Authorization header and decodes it.
  # Ensures the token has the 'access' purpose.
  #
  # @return [Hash] The decoded payload of the access token (symbolized keys).
  # @raise [MissingTokenError] If the Authorization header is missing or malformed.
  # @raise [InvalidTokenError] If the token is invalid or signature verification fails.
  # @raise [ExpiredTokenError] If the token has expired.
  # @raise [InvalidTokenPurposeError] If the token's purpose is not 'access'.
  def decode_access_token_from_header
    token = get_token_from_header
    decode(token, PURPOSE_ACCESS) # Decode and verify purpose is 'access'
  end

  # Returns the currently authenticated user based on the access token in the header.
  # Uses memoization (@current_user) to avoid redundant lookups within the same request cycle.
  #
  # @return [User, nil] The authenticated User object or nil if authentication fails or user not found.
  def current_user
    # If already computed in this request, return memoized value.
    # Checks if the instance variable is defined; nil is a valid memoized value (e.g., if lookup failed).
    return @current_user if defined?(@current_user)

    # Attempt to find the user, memoize the result (even if nil).
    @current_user = find_user_from_access_token
  end

  # Checks if a user is currently logged in (authenticated).
  #
  # @return [Boolean] True if `current_user` returns a user object, false otherwise.
  def logged_in?
    current_user.present?
  end

  # --- Private Helper Methods ---
  private

  # The main authentication method called by the `before_action` hook.
  # It attempts to find the current user based on the Authorization header.
  # If authentication fails due to missing/invalid/expired token or user not found,
  # it renders an appropriate JSON error response with status 401 Unauthorized
  # and halts the request chain.
  def authenticate
    # Attempt to load the user. This triggers token decoding and user lookup.
    # If current_user returns nil (due to UserNotFoundError or token issues caught within find_user_from_access_token),
    # the `unless logged_in?` check will fail.
    unless logged_in?
      # If `find_user_from_access_token` didn't raise an error but returned nil (e.g., User.find_by returned nil),
      # we render a generic unauthorized error here. Specific token errors are handled below.
      # This situation implies the token was valid but the user ID within it doesn't exist anymore.
      render_unauthorized(error_code: "user_not_found", description: "User associated with token not found.")
    end

  # Rescue specific authentication errors raised during `current_user` lookup
  # (which calls `find_user_from_access_token`, which calls `decode_access_token_from_header`, which calls `decode`).
  rescue MissingTokenError => e
    render_unauthorized(error_code: "missing_token", description: e.message)
  rescue ExpiredTokenError => e
    render_unauthorized(error_code: "token_expired", description: e.message)
  rescue InvalidTokenPurposeError => e
    render_unauthorized(error_code: "invalid_token_purpose", description: e.message)
  rescue InvalidTokenError => e # Catches general invalid token issues (signature, format, iss, aud, etc.)
    render_unauthorized(error_code: "invalid_token", description: e.message)
  rescue UserNotFoundError => e # Explicitly catch if find_user raises this (optional)
     render_unauthorized(error_code: "user_not_found", description: e.message)
    # It's generally good practice to avoid rescuing StandardError directly.
    # If other unexpected errors occur, let Rails handle them (500 Internal Server Error).
  end

  # Helper method to render a standard 401 Unauthorized JSON response.
  #
  # @param error_code [String] A machine-readable error code.
  # @param description [String] A human-readable error description.
  def render_unauthorized(error_code:, description:)
    render json: { error: error_code, error_description: description }, status: :unauthorized
  end


  # Finds the user associated with the access token from the request header.
  #
  # @return [User, nil] The User object if found and token is valid. Returns nil if user not found.
  # @raise [MissingTokenError, InvalidTokenError, ExpiredTokenError, InvalidTokenPurposeError] If token decoding fails.
  # @raise [UserNotFoundError] If the user ID from a valid token does not correspond to an existing user.
  def find_user_from_access_token
    # Decode the access token. This will raise errors if the token is invalid/expired/missing etc.
    payload = decode_access_token_from_header
    user_id = payload.dig(PAYLOAD_DATA_KEY, PAYLOAD_ID_KEY)

    # Ensure user ID is present in the payload after successful decoding
    raise InvalidTokenError, "User ID not found in token payload" unless user_id

    # Find the user by the ID stored in the token's data claim.
    # Use `find_by` which returns nil if not found, instead of `find` which raises ActiveRecord::RecordNotFound.
    user = User.find_by(id: user_id)

    # If the user wasn't found for a valid token (e.g., deleted after token issuance)
    raise UserNotFoundError, "User with ID #{user_id} not found" unless user

    user

    # Note: We don't rescue ActiveRecord::RecordNotFound here anymore because find_by is used.
    # Instead, we explicitly raise UserNotFoundError if find_by returns nil.
    # Errors from `decode_access_token_from_header` bubble up and are caught by `authenticate`.
  end

  # Encodes a payload into a JWT token with specified expiry and purpose.
  #
  # @param payload [#id] The object containing data to encode (must respond to `#id`).
  # @param expiry_seconds [Integer] The token's lifespan in seconds from now.
  # @param purpose [String] The purpose of the token (e.g., 'access', 'refresh').
  # @return [String] The generated JWT string.
  # @raise [ArgumentError] If payload does not respond to #id.
  def encode_token(payload, expiry_seconds, purpose)
    # Ensure payload has an ID.
    raise ArgumentError, "Payload must respond to #id" unless payload.respond_to?(:id)

    now = Time.now.to_i
    token_payload = {
      # --- Custom Claims ---
      PAYLOAD_DATA_KEY => {
        PAYLOAD_ID_KEY => payload.id # Store application-specific data under a namespace
      },
      PAYLOAD_PURPOSE_KEY => purpose, # Our custom claim for token type

      # --- Standard JWT Claims (Registered Claim Names) ---
      :exp => now + expiry_seconds.to_i, # Expiration Time
      :iat => now,                       # Issued At
      :nbf => now,                       # Not Before
      :iss => JWT_ISSUER,                # Issuer
      :aud => JWT_AUDIENCE,              # Audience
      :sub => payload.id.to_s,           # Subject (usually user identifier)
      :jti => SecureRandom.uuid          # JWT ID (unique identifier for this token)
    }

    # Encode the payload using the secret key and algorithm.
    JWT.encode(token_payload, jwt_secret, JWT_ALGORITHM)
  end

  # Retrieves the JWT secret key.
  # Reads from the JWT_SECRET environment variable.
  #
  # @note Ensure this secret is strong and kept confidential.
  # @return [String] The JWT secret key.
  # @raise [RuntimeError] If the JWT_SECRET environment variable is not set.
  def jwt_secret
    # Memoize the secret lookup for efficiency within a request.
    @jwt_secret ||= ENV["JWT_SECRET"].tap do |secret|
      # Although the initializer checks on boot, this adds an extra layer
      # in case the ENV var becomes unset during runtime (less likely but possible).
      raise "JWT_SECRET environment variable must be set!" if secret.blank?
    end
  end

  # Extracts the JWT token from the 'Authorization: Bearer <token>' header.
  #
  # @return [String] The extracted token string.
  # @raise [MissingTokenError] If the header is missing, malformed, or doesn't contain a token.
  def get_token_from_header
    auth_header = request.headers["Authorization"]
    raise MissingTokenError, "Authorization header is missing" unless auth_header

    # Match "Bearer <token>" format, allowing for potential extra whitespace.
    match_data = auth_header.match(/^Bearer\s+(.+)$/i) # Case-insensitive match for "Bearer"
    token = match_data&.captures&.first

    raise MissingTokenError, "Authorization header format is invalid or token is missing" if token.blank?

    token
  end
end
