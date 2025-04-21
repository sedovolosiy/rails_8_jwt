class V1::AuthController < ApplicationController
  # Skip the :authenticate before_action for the :login action, as it's for logging in.
  allow_unauthenticated_access only: [ :login ]

  def login
    user = User.find_by(email_address: params[:email_address])

    if user && user.authenticate(params[:password])
      access_token = encode_access_token(user)
      refresh_token = encode_refresh_token(user)

      # Возвращаем refresh_token в теле ответа, cookie не используем
      response.headers["Cache-Control"] = "no-store"
      response.headers["Pragma"] = "no-cache"

      render json: {
        access_token: access_token,
        refresh_token: refresh_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_EXPIRY.to_i
      }, status: :ok
    else
      render json: { error: "invalid_credentials", error_description: "Invalid email or password" }, status: :unauthorized
    end
  end

  # Optional: Add a logout action (no cookie to clear)
  def destroy
    head :no_content
  end
end
