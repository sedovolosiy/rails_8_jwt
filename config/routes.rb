Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  namespace :v1 do
    # Authentication routes
    post "auth/login", to: "auth#login"
    post "auth/refresh", to: "refresh#create" # New refresh endpoint
    delete "auth/logout", to: "auth#destroy" # Optional logout endpoint

    # User routes
    get "users/me", to: "users#me"
  end
end
