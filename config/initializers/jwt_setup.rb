# frozen_string_literal: true

# This initializer checks for the presence of the JWT_SECRET environment variable
# on application startup. It prevents the application from running
# without a properly configured secret, which is crucial for security.

jwt_secret = ENV["JWT_SECRET"]

if jwt_secret.blank?
  raise "JWT_SECRET environment variable must be set!"
end

# Optional: Log that the check passed (useful for debugging startup)
# Rails.logger.info "JWT secret check passed."