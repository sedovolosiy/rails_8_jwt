class V1::UsersController < ApplicationController
  def me
    if current_user
      render json: { user: current_user }, status: :ok
    else
      render json: { error: "Invalid token" }, status: :unauthorized
    end
  end
end
