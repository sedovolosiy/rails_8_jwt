# Rails 8 JWT API

This project is an example of an API built with Ruby on Rails 8 using JWT (JSON Web Token) authentication.

## Features

- User registration and authentication with JWT (access/refresh tokens)
- API-only application (no views)
- Data serialization with Alba
- Uses Solid Cache and Solid Queue for caching and background jobs
- Production-ready Dockerfile
- Example tests and fixtures

## Quick Start

1. Clone the repository and install dependencies:
   ```sh
   bundle install
   ```

2. Copy the example environment variables and set the secret:
   ```sh
   cp .example.env .env
   # edit .env and set JWT_SECRET
   # openssl rand -base64 32 to generate new JWT_SECRET
   ```

3. Prepare the database:
   ```sh
   bin/rails db:setup
   ```

4. Start the server:
   ```sh
   bin/rails server
   ```

## Request Examples

The `api-test.http` file contains example HTTP requests for testing the API (login, refresh, get current user).

## Main Endpoints

- `POST /v1/auth/login` — login with email and password, get access/refresh tokens
- `POST /v1/auth/refresh` — refresh access token using refresh token
- `GET /v1/users/me` — get current user info (using access token)

## Tests

To run tests:
```sh
bin/rails test
```

## Docker

To build and run with Docker:
```sh
docker build -t rails_8_jwt .
docker run -d -p 80:80 --name rails_8_jwt rails_8_jwt
```

## Environment Variables

- `JWT_SECRET` — secret for signing JWT (required)

## License

MIT
