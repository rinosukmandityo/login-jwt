# `generate` generates test mocks.
# go get github.com/matryer/moq@latest
generate:
	go generate

test:
	go test ./... -v -race -cover -coverprofile=coverage.txt && go tool cover -func=coverage.txt
	