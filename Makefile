# Simple Makefile for a Go project

# Build the application
all: build test

templ-install:
	@if ! command -v templ > /dev/null; then \
		read -p "Go's 'templ' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
		if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
			go install github.com/a-h/templ/cmd/templ@latest; \
			if [ ! -x "$$(command -v templ)" ]; then \
				echo "[Make] templ installation failed. Exiting..."; \
				exit 1; \
			fi; \
		else \
			echo "[Make] You chose not to install templ. Exiting..."; \
			exit 1; \
		fi; \
	fi

tailwind:
	@if [ ! -f tailwindcss ]; then curl -sL https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 -o tailwindcss; fi

	@chmod +x tailwindcss

build: tailwind templ-install
	@echo "[Make] Building Templ"
	@templ generate

	@echo "[Make] Building tailwindcss"
	@./tailwindcss -i views/assets/css/input.css -o views/assets/css/output.css

	@echo "[Make] Building GO"
	@go build -o dist/main cmd/api/main.go

	@echo "[Make] Build Completed..."

# Run the application
run:
	@go run cmd/api/main.go

# Test the application
test:
	@echo "[Make] Testing..."
	@go test ./... -v

# Clean the binary
clean:
	@echo "[Make] Cleaning..."
	@rm -rf dist
	@rm -rf tmp
	@rm -rf log/*

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "[Make] Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "[Make] Watching...";\
            else \
                echo "[Make] You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

.PHONY: all build run test clean watch tailwind templ-install