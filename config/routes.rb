Rails.application.routes.draw do
  namespace :v1 do
    resources :auth, only: [ :create ]
    resources :users, only: [] do
      collection do
        get :me
      end
    end
  end

  get "up" => "rails/health#show", as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
