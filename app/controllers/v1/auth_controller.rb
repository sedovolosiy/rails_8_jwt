class V1::AuthController < ApplicationController
  allow_unauthenticated_access only: [ :login, :signup ]

  def login
    user = User.find_by(email_address: params[:email_address])

    if user && user.authenticate(params[:password])
      render_auth_tokens(user, :ok)
    else
      render json: {
        error: "invalid_credentials",
        error_description: "Invalid email or password"
      }, status: :unauthorized
    end
  end

  def signup
    user = User.new(user_params)
    if user.save
      render_auth_tokens(user, :created)
    else
      render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
    end
  end

  def destroy
    head :no_content
  end

  private

  def render_auth_tokens(user, status)
    set_cache_headers
    render json: auth_tokens_response(user), status: status
  end

  def auth_tokens_response(user)
    {
      access_token: encode_access_token(user),
      refresh_token: encode_refresh_token(user),
      token_type: "Bearer",
      expires_in: ACCESS_TOKEN_EXPIRY.to_i,
      refresh_token_expires_in: REFRESH_TOKEN_EXPIRY.to_i
    }
  end

  def set_cache_headers
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
  end

  def user_params
    params.require(:auth).permit(:email_address, :password, :password_confirmation)
  end
end
