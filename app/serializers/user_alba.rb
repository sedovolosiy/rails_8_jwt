# filepath: app/serializers/user_alba.rb
class UserAlba
  include Alba::Resource

  attributes :id, :email_address
  # Add other attributes you want to expose here
end
