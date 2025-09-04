# User Authentication & Management API

[![PHP Version](https://img.shields.io/badge/PHP-8.4-blue)](https://www.php.net/)
[![Symfony](https://img.shields.io/badge/Symfony-7.3-green)](https://symfony.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-ready-blue)](https://www.docker.com/)

A production-ready REST API for user authentication and management built with modern PHP practices and enterprise-grade security.

## Features

- **Complete Authentication Flow** - Registration, login, email verification, and password reset
- **JWT Token Management** - Secure stateless authentication with configurable expiration
- **Role-Based Access Control** - Admin and user roles with granular permissions
- **User Administration** - Full CRUD operations with suspend/unsuspend functionality
- **Email Integration** - Automated welcome emails and password reset notifications
- **Production Ready** - Docker containerization with PostgreSQL and Redis

## Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | Symfony 7.3 |
| Language | PHP 8.4 |
| Database | PostgreSQL 15+ |
| Cache/Queue | Redis 7 |
| Server | FrankenPHP + Caddy |
| Testing | PHPUnit |

## Quick Start

### Prerequisites
- Docker & Docker Compose (v2.10+)

### Setup
```bash
# Clone and build
docker compose build --no-cache
docker compose up --wait

# Access API
curl https://localhost/guest/registration \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"password123"}'
```

## API Overview

### Authentication Endpoints
| Endpoint | Method | Description |
|----------|---------|-------------|
| `/guest/registration` | POST | Register new user account |
| `/guest/login` | POST | Authenticate and receive JWT |
| `/guest/activate-account/{token}` | GET | Activate user account |
| `/guest/forgot-password` | POST | Request password reset |
| `/guest/reset-password` | POST | Reset password with token |
| `/guest/resend-activation` | POST | Resend activation email |

### User Management Endpoints
| Endpoint | Method | Description | Auth Required |
|----------|---------|-------------|---------------|
| `/user` | GET | List all users with filters | ✓ |
| `/user/{id}` | GET | Get user details | ✓ |
| `/user/{id}` | PATCH | Update user properties | ✓ Admin |
| `/user/{id}` | DELETE | Delete user account | ✓ Admin |
| `/user/{id}/suspend` | POST | Suspend user account | ✓ Admin |
| `/user/{id}/unsuspend` | POST | Unsuspend user account | ✓ Admin |

## Project Structure

```
src/
├── Controller/     # HTTP request handlers
├── Entity/         # Doctrine ORM models
├── Service/        # Business logic layer
├── DTO/           # Data transfer objects
├── Security/      # Authentication & authorization
└── Exception/     # Custom exception classes
```

# Used libraries
- composer require symfony/orm-pack
- composer require --dev symfony/maker-bundle
- composer require firebase/php-jwt
- composer require symfony/serializer-pack
- composer require symfony/uid
- composer require symfony/security-bundle
- composer require --dev symfony/profiler-pack
- composer require --dev symfony/test-pack
- composer require symfony/rate-limiter
- composer require symfony/validator
- composer require symfony/mailer
- composer require symfony/mailtrap-mailer
- composer require symfony/messenger
- composer require symfony/redis-messenger