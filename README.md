
# NFeApp

NFeApp is a web application for managing electronic invoices (Notas Fiscais Eletrônicas) with a secure, modular Go backend and a modern templ-based frontend.

## Features

- Secure HTTP/HTTPS server with best-practice timeouts and graceful shutdown
- Modular code structure: repository, routes, handlers, templates
- SQLite database with security-focused configuration
- Session management and periodic cleanup
- Static file serving
- Templ-based HTML rendering
- Security headers middleware

## Requirements

- Go 1.24+
- [templ](https://templ.guide/) (for HTML templates)
- SQLite3

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/nfe.git
cd nfe
```

### 2. Generate self-signed certificates (for HTTPS)

```bash
./gencerts
```

### 3. Build the project

```bash
go build -o nfeapp
```

### 4. Run the application

#### Development (HTTP)

```bash
./nfeapp
```

#### Production (HTTPS)

Set `Production: true` in your `config.yaml` and run:

```bash
./nfeapp
```

## Project Structure

```
.
├── cmd/            # (optional) Main application entrypoint
├── handler/        # HTTP handlers
├── repository/     # Database/repository layer
├── routes/         # Route and middleware setup
├── templates/      # Templ HTML components
├── static/         # Static assets (CSS, JS, images)
├── config.yaml     # Application configuration
├── gencerts        # Certificate generation script
├── main.go         # Application bootstrap
└── README.md
```

## Configuration

Edit `config.yaml` to set application options (e.g., production mode, session settings).

## Security

- Uses secure HTTP headers
- Restricts SQLite file permissions
- Enables SQLite foreign keys and WAL mode
- Graceful shutdown on interrupt

## License

MIT

---

**Made with Go and

https://github.com/chatzijohn/htmx-go-app

https://docs.github.com/en/copilot/customizing-copilot/adding-repository-custom-instructions-for-github-copilot
