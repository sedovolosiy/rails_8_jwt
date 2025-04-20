class V1::UsersController < ApplicationController
  def me
    user = current_user
    if user
      render json: UserAlba.new(user).serialize, status: :ok
    else
      render json: { error: "Invalid token" }, status: :unauthorized
    end
  end
end
