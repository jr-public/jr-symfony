# API Starter: Symfony User & Auth

![Project Status](https://img.shields.io/badge/status-in%20development-blue)
[![PHP Version](https://img.shields.io/badge/PHP-8.4-blue)](https://www.php.net/)
[![Symfony](https://img.shields.io/badge/Symfony-7.3-green)](https://symfony.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue)](https://www.docker.com/)

Designed as a portfolio showcase and a jumping-off point for future applications, this REST API functions as a User Management and Authentication system, providing endpoints for registration, login, token refresh, and user profile management.

## Project Status

Currently under active development. While the core features are functional and stable, the codebase is actively being refined, and features are still being added.

## Features

- **Complete Authentication Flow** - Registration, login, email verification, and password reset
- **JWT Token Management** - Secure stateless authentication with configurable expiration
- **Role-Based Access Control** - Admin and user roles with granular permissions
- **User Administration** - Full CRUD operations with suspend/unsuspend functionality
- **Email Integration** - Automated emails for common features: registration, password reset, and others

| Component | Technology |
|-----------|------------|
| Framework | Symfony 7.3 |
| Language | PHP 8.4 |
| Database | PostgreSQL 15+ |
| Cache/Queue | Redis 7 |
| Testing | PHPUnit |

# Deployment

## Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/jr-public/jr-symfony
   cd jr-symfony
   ```

2. **Start the application**
   ```bash
   docker compose up --build --pull always --wait
   ```

3. **Initialize the database with sample data**
   ```bash
   docker compose exec php bin/console app:seed
   ```

The application will be available at:
- **API**: http://localhost:80
- **Database**: localhost:5432 (PostgreSQL)
- **Redis**: localhost:6379


## API Documentation

**View the live API docs** for the deployed version at: 
Once your application is running, you can access interactive API documentation through Swagger UI:

**Swagger UI**: [http://localhost/api/doc](http://localhost/api/doc)

This provides an interactive interface where you can:
- Browse all available endpoints
- View request/response schemas
- Test endpoints directly with example payloads
- See authentication requirements for each endpoint

**Raw OpenAPI Specification**: [http://localhost/api/doc.json](http://localhost/api/doc.json)

## Cleanup Commands

**Remove old volumes** (if you need a fresh start):
```bash
docker compose down --remove-orphans -v
```

**Copy vendor files** to your local machine (for IDE autocomplete):
```bash
# Find the PHP container ID
docker ps

# Copy vendor directory (replace PHP_APP_ID with actual container ID)
docker cp PHP_APP_ID:/app/vendor ./
```
