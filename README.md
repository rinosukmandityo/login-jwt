## Quotes Servie
A service for login with jwt by implementing Domain Driven Design (DDD) and Clean Architecture.

Detail documentation can be found in [docs/api_auth.md](docs/api_auth.md) and [docs/api.md](docs/api.md)

### How to run
- Set the environment variable JWT secret with key `jwt_secret`, for example: `export jwt_secret=secret.key`
- Go to `cmd/auth` or `cmd/user` directory
- Run `go run main.go` command
- It will run on port `8080`
- Open `localhost:8080` in the browser and start sending the api request

### How to test
- On root directory run `make test` command
