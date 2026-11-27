# JWT Project: Incremental Python & Docker Auth Architecture

A modular, multi-container authentication and authorization system built with **FastAPI**, **PostgreSQL**, **Redis**, and **Docker**. This project demonstrates production JWT patterns from basic authentication to asymmetric microservices security.

## Architecture & Key Concepts
* **Stateless RBAC:** Embeds user roles (`free`, `premium`, `admin`) directly into signed JWT claims for zero-db-query route protection.
* **Two-Token Rotation:** Issues short-lived **Access Tokens** (15 min) alongside long-lived **Refresh Tokens** (7 days).
* **Instant Revocation:** Uses **Redis** with automatic TTL expiration to blacklist logged-out tokens.
* **Asymmetric Microservices (`RS256`):** `auth-service` signs tokens with a **Private Key**, while `billing-service` verifies them independently using **only the Public Key**.

---

## Quick Start

### 1. Clone & Configure Environment
```bash
git clone <your-repo-url>
cd jwt-mastery-saas
cp .env.example .env
```

### 2. Generate RSA Key Pair
Run the helper script to generate `keys/private.pem` and `keys/public.pem`:
```bash
chmod +x generate_keys.sh
./generate_keys.sh
```

### 3. Start the Containers
```bash
docker-compose up --build
```
* **Auth Service Swagger UI:** `http://localhost:8000/docs`
* **Billing Service Swagger UI:** `http://localhost:8001/docs`

---

## API Endpoints

### Auth Service (`:8000`)

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/register` | Public | Create a user (`free`, `premium`, or `admin`). |
| `POST` | `/login` | Public | Returns an `access_token` and `refresh_token`. |
| `POST` | `/refresh` | Refresh Token | Exchanges a valid refresh token for a new access token. |
| `POST` | `/logout` | Bearer Token | Blacklists both access and refresh tokens in Redis. |
| `GET` | `/free-content` | Any Authenticated | Accessible by all valid users. |
| `GET` | `/premium-content` | `premium`, `admin` | Restricted by JWT `role` claim. |
| `DELETE` | `/admin/nuke` | `admin` | Restricted to admins only. |

### Billing Service (`:8001`)

| Method | Endpoint | Access | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/invoices` | Any Authenticated | Verifies JWT via `public.pem` and returns user invoices. |
| `POST` | `/refund/{id}` | `admin` | Verifies admin role independently without DB access. |
