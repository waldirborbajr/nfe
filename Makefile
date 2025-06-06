.PHONY: run
run:
	templ generate
	go run ./...

fmt:
	templ fmt ./views
	go fmt ./...