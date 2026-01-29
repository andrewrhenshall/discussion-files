# Database Architecture

CitadelSecure uses per-customer isolated databases for complete tenant separation.

## Database Types

| Database | Purpose | Isolation |
|----------|---------|-----------|
| **Metadata DB** | Customer routing, external user access | 1 shared instance |
| **Customer DBs** | All tenant GRC data (users, assets, compliance) | 1 per customer |
| **Redis** | Sessions, task queue (Huey), caching | 1 per customer |
| **Router Redis** | OAuth authorization codes | 1 shared instance |

---

## Dev Environment (Docker)

Local development uses Docker containers defined in `docker-compose.isolated-stacks-ssr.yml`.

### Containers

| Container | Port | Database | Purpose |
|-----------|------|----------|---------|
| `citadel-postgres-metadata` | 5432 | `ciso_assistant` | Customer domain routing |
| `citadel-acme-db` | 5433 | `acme_db` | ACME tenant data |
| `citadel-techstart-db` | 5434 | `techstart_db` | TechStart tenant data |
| `citadel-medcorp-db` | 5435 | `medcorp_db` | MedCorp tenant data |
| `citadel-acme-redis` | 6380 | - | ACME sessions/cache |
| `citadel-techstart-redis` | 6381 | - | TechStart sessions/cache |
| `citadel-medcorp-redis` | 6382 | - | MedCorp sessions/cache |
| `citadel-router-redis` | 6379 | - | Auth codes |

### Credentials (Dev Only)

```
User: ciso_user
Password: ciso_local_password_123
```

### Quick Commands

```bash
# Query customer database
docker exec citadel-acme-db psql -U ciso_user -d acme_db -c "SELECT email FROM iam_user;"

# Query metadata database
docker exec citadel-postgres-metadata psql -U ciso_user -d ciso_assistant -c "SELECT * FROM customer_domains;"

# Check Redis
docker exec citadel-acme-redis redis-cli KEYS "*"
```

---

## Production Environment (AWS)

Production uses Terraform-provisioned AWS services in `infrastructure/terraform/`.

### Services

| Service | Resource | Per-Customer |
|---------|----------|--------------|
| **RDS PostgreSQL** | `db.t3.micro`+ | Yes (isolated instances) |
| **ElastiCache Redis** | `cache.t3.micro`+ | Yes (isolated clusters) |
| **Secrets Manager** | DB credentials, JWT keys | Yes |

### Metadata vs Customer RDS

| Setting | Metadata RDS | Customer RDS |
|---------|--------------|--------------|
| Database | `ciso_assistant` | `{subdomain}_db` |
| Instance Count | 1 (shared) | 1 per customer |
| Multi-AZ | Yes (prod) | Yes (prod) |
| Accessed By | Router + all backends | Single customer backend |

### Production Settings

| Setting | Dev | Production |
|---------|-----|------------|
| Multi-AZ | No | Yes |
| Deletion Protection | No | Yes |
| Final Snapshot | Skip | Required |
| Backup Retention | 7 days | 7 days |
| Encryption at Rest | Yes | Yes |
| Public Access | No | No |
| Redis TLS | No (`redis://`) | Yes (`rediss://`) |

### Secrets Manager Structure

```
citadelsecure/{env}/db/metadata          # Metadata DB credentials
citadelsecure/{env}/db/{customer}        # Customer DB credentials
citadelsecure/{env}/jwt-private-key      # Router JWT signing key
citadelsecure/{env}/jwt-public-key       # Backend JWT verification
citadelsecure/{env}/django/{customer}    # Django SECRET_KEY
```

### Adding a Customer (Terraform)

```hcl
# In infrastructure/terraform/environments/dev/main.tf
customer_configs = {
  "acme"        = { email_domain = "acme.com" }
  "newcustomer" = { email_domain = "newcustomer.com" }  # Add this
}
```

Then: `terraform plan && terraform apply`

Creates: RDS instance + ElastiCache cluster + ECS services + ALB rules + Secrets

---

## Metadata Database Schema

Stores routing data only. Created by router service on startup.

### customer_domains

Maps email domains to customer infrastructure.

| Column | Type | Purpose |
|--------|------|---------|
| `customer_subdomain` | VARCHAR(100) | `acme`, `techstart` |
| `email_domain` | VARCHAR(255) | `acme.com` (indexed) |
| `database_name` | VARCHAR(100) | `acme_db` |
| `db_host` | VARCHAR(255) | Container/RDS hostname |
| `backend_port` | INTEGER | Dev only (8000/8001/8002) |
| `is_active` | BOOLEAN | Soft delete |

### cross_customer_access

External users (auditors) with multi-tenant access.

| Column | Type | Purpose |
|--------|------|---------|
| `user_email` | VARCHAR(255) | `alice@auditor.com` |
| `customer_subdomain` | VARCHAR(100) | `acme` |
| `role_names` | TEXT[] | `['reader', 'analyst']` |
| `expires_at` | TIMESTAMP | Temporal access control |
| `granted_by` | VARCHAR(255) | Audit trail |

---

## Connection Flow

### Backend Configuration

Set via environment variables (Docker) or Secrets Manager (AWS).

```python
# backend/ciso_assistant/settings.py
DATABASES = {
    "default": {  # Customer database
        "NAME": os.environ["POSTGRES_NAME"],  # e.g., "acme_db"
        "HOST": os.environ["DB_HOST"],
    },
    "metadata": {  # Read-only metadata access
        "HOST": os.environ["METADATA_DB_HOST"],
        "OPTIONS": {"options": "-c default_transaction_read_only=on"},
    },
}
```

### Database Router

`backend/ciso_assistant/db_routers.py` ensures:
- All ORM queries go to customer database (`default`)
- Metadata queries use raw SQL only
- Migrations never run on metadata database

### Login Flow

1. User submits email to router service
2. Router queries `customer_domains` by email domain
3. Router returns customer subdomain + signs JWT
4. Frontend redirects to customer backend
5. Backend verifies JWT, queries customer database

### External User Flow

1. Auditor email not in `customer_domains`
2. Router checks `cross_customer_access` table
3. Returns list of accessible customers
4. User selects customer, backend assigns roles from `role_names`

---

## Migrations

### Customer Databases

Normal Django migrations, run on each backend startup:

```bash
python manage.py migrate  # Applies to POSTGRES_NAME database
```

### Metadata Database

**No Django migrations.** Tables created by router service:

```python
# router-service/app.py - runs on startup
@app.on_event("startup")
def startup_event():
    seed_customer_domains()  # CREATE TABLE IF NOT EXISTS
```

---

## Key Files

| File | Purpose |
|------|---------|
| `docker-compose.isolated-stacks-ssr.yml` | Dev database containers |
| `backend/ciso_assistant/settings.py` | Django DB configuration |
| `backend/ciso_assistant/db_routers.py` | ORM routing rules |
| `router-service/app.py` | Metadata table creation |
| `infrastructure/terraform/modules/rds/` | Production RDS module |
| `infrastructure/terraform/modules/elasticache/` | Production Redis module |
| `infrastructure/terraform/modules/customer-stack/` | Per-tenant infrastructure |

---

## Related Docs

- [ARCHITECTURE_COMPACT.md](../../ARCHITECTURE_COMPACT.md) - Infrastructure overview
- [AUTH_FLOW.md](../../AUTH_FLOW.md) - Login/logout flows
- [INTEGRATION_ARCHITECTURE.md](./INTEGRATION_ARCHITECTURE.md) - AWS integrations
