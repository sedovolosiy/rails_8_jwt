class V1::RefreshController < ApplicationController
  # This controller doesn't need standard access token authentication
  # It relies solely on the refresh token cookie.
  allow_unauthenticated_access only: [ :create ]

  def create
    refresh_token = params[:refresh_token] || request.headers["X-Refresh-Token"]

    unless refresh_token
      return render json: { error: "missing_token", error_description: "Refresh token not provided" }, status: :unauthorized
    end

    begin
      # Decode the refresh token, expecting 'refresh' purpose
      decoded_payload = decode(refresh_token, "refresh")
      user_id = decoded_payload.dig("data", "id")

      unless user_id
        raise JWT::DecodeError, "User ID not found in refresh token payload"
      end

      user = User.find(user_id) # Raises ActiveRecord::RecordNotFound if user doesn't exist

      # Issue a new access token
      new_access_token = encode_access_token(user)

      # Prevent caching
      response.headers["Cache-Control"] = "no-store"
      response.headers["Pragma"] = "no-cache"

      render json: {
        access_token: new_access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_EXPIRY.to_i
      }, status: :ok

    rescue ActiveRecord::RecordNotFound
      render json: { error: "invalid_token", error_description: "User associated with refresh token not found" }, status: :unauthorized
    rescue JWT::ExpiredSignature
      render json: { error: "token_expired", error_description: "Refresh token has expired" }, status: :unauthorized
    rescue JWT::DecodeError => e
      render json: { error: "invalid_token", error_description: "Refresh token is invalid: #{e.message}" }, status: :unauthorized
    end
  end
end
