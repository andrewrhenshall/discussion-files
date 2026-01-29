# CitadelSecure Architecture (Compact Reference)

**Purpose**: Quick reference for understanding system architecture during development
**Last Updated**: 2025-12-16

---

## Core Concept: Isolated Instances

**Why**: CISO Assistant has hardcoded `view_all_users=True` - users see ALL data across ALL tenants. True multi-tenancy would require 6+ months refactoring.

**Solution**: Each customer gets completely isolated infrastructure:
- Separate ECS Fargate container (Django + Frontend)
- Separate PostgreSQL database
- Separate Redis cache
- ALB routes subdomains to correct container

```
acme.app.citadelsecure.com    → Acme's ECS Task    → acme_db
techstart.app.citadelsecure.com → TechStart's Task → techstart_db
medcorp.app.citadelsecure.com   → MedCorp's Task   → medcorp_db
```

---

## Current Local Architecture (SSR Isolated Stacks)

**Docker Compose**: `docker-compose.isolated-stacks-ssr.yml`

```
┌─────────────────────────────────────────────────────────────┐
│  http://login.local/login  (Centralized Login)              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Router Service (FastAPI) - Port 9100               │   │
│  │  - Authenticates against correct customer DB        │   │
│  │  - Generates JWT, redirects to customer subdomain   │   │
│  └─────────────────────────────────────────────────────┘   │
│                           ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Nginx Router - Port 80                              │   │
│  │  login.local → router:9100                           │   │
│  │  acme.local → acme-frontend:3000                     │   │
│  │  techstart.local → techstart-frontend:3000           │   │
│  │  medcorp.local → medcorp-frontend:3000               │   │
│  └─────────────────────────────────────────────────────┘   │
│                           ↓                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Acme Stack  │  │TechStart    │  │ MedCorp     │        │
│  │ Frontend:3000│  │Frontend:3000│  │Frontend:3000│        │
│  │ Backend:8000 │  │Backend:8000 │  │Backend:8000 │        │
│  │ DB:5433     │  │DB:5434      │  │DB:5435      │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                              │
│  postgres-metadata:5432 (CustomerDomain routing only)       │
└─────────────────────────────────────────────────────────────┘
```

---

## AWS Architecture (Production)

**Terraform**: `infrastructure/terraform/environments/dev/`

```
┌─────────────────────────────────────────────────────────────────┐
│  https://login.getcitadelsecure.com  (Centralized Login)        │
│  https://acme.app.getcitadelsecure.com  (Customer App)          │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  ALB (Application Load Balancer) + ACM Certificate       │   │
│  │  - HTTPS termination (*.app.getcitadelsecure.com)        │   │
│  │  - Host-based routing to target groups                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  ECS Fargate Cluster (citadelsecure-cluster-dev)         │   │
│  │                                                           │   │
│  │  ┌─────────────┐                                         │   │
│  │  │ Router      │  login.* → :9100                        │   │
│  │  │ (FastAPI)   │  Signs JWTs, routes to customer backend │   │
│  │  └─────────────┘                                         │   │
│  │                                                           │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │   │
│  │  │ Acme Stack  │  │TechStart    │  │ MedCorp     │      │   │
│  │  │ Frontend    │  │Frontend     │  │Frontend     │      │   │
│  │  │ Backend     │  │Backend      │  │Backend      │      │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           ↓                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Data Layer (Per Customer Isolation)                      │   │
│  │                                                           │   │
│  │  RDS PostgreSQL 15.8        ElastiCache Redis 7.0        │   │
│  │  ┌─────────┐ ┌─────────┐   ┌─────────┐ ┌─────────┐      │   │
│  │  │metadata │ │acme_db  │   │router   │ │acme     │      │   │
│  │  │   DB    │ │techstart│   │redis    │ │redis    │      │   │
│  │  │         │ │medcorp  │   │         │ │...      │      │   │
│  │  └─────────┘ └─────────┘   └─────────┘ └─────────┘      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│  S3: citadelsecure-evidences-dev (Evidence storage)             │
│  Secrets Manager: JWT keys, DB credentials, Django secrets      │
│  CloudWatch: /ecs/citadelsecure-dev (centralized logging)       │
└─────────────────────────────────────────────────────────────────┘
```

### AWS Services Used

| Service | Purpose | Resource Names |
|---------|---------|----------------|
| **ECS Fargate** | Container orchestration | `citadelsecure-cluster-dev` |
| **ALB** | Load balancing + HTTPS | `citadelsecure-alb-dev` |
| **ACM** | SSL certificates | `*.app.getcitadelsecure.com` |
| **RDS** | PostgreSQL databases | `citadelsecure-{customer}-dev` |
| **ElastiCache** | Redis caching | `citadelsecure-{customer}-dev` |
| **ECR** | Container registry | `citadelsecure/{frontend,backend,router}` |
| **S3** | Evidence storage | `citadelsecure-evidences-dev` |
| **Secrets Manager** | Sensitive config | `citadelsecure/dev/*` |
| **CloudWatch** | Logs & monitoring | `/ecs/citadelsecure-dev` |
| **VPC** | Network isolation | Private subnets, NAT Gateway |

### Terraform Modules

```
infrastructure/terraform/
├── environments/
│   └── dev/
│       └── main.tf          # Customer configs, module composition
└── modules/
    ├── networking/          # VPC, subnets, security groups, NAT
    ├── alb/                 # Load balancer, ACM cert, listeners
    ├── ecs-cluster/         # ECS cluster, IAM roles, CloudWatch
    ├── ecr/                 # Container registries (prevent_destroy)
    ├── s3/                  # Evidence bucket
    ├── secrets/             # JWT keys, metadata DB creds
    ├── router/              # Router ECS service + ElastiCache
    ├── customer-stack/      # Per-customer: RDS, Redis, frontend, backend
    ├── rds/                 # Reusable RDS module
    └── elasticache/         # Reusable ElastiCache module
```

### Adding a New Customer

1. Add to `customer_configs` in `environments/dev/main.tf`:
```hcl
customer_configs = {
  acme = { email_domain = "acme.com", superuser_email = "admin@acme.com" }
  newcorp = { email_domain = "newcorp.io", superuser_email = "admin@newcorp.io" }  # NEW
}
```

2. Apply:
```bash
cd infrastructure/terraform/environments/dev
~/bin/terraform.exe plan -out=tfplan && ~/bin/terraform.exe apply tfplan
```

3. Seed customer data:
```bash
python scripts/provision-customer.py newcorp
```

### Cost Management

**To save costs** (stop all running services):
```bash
# Scale ECS to 0
aws ecs update-service --cluster citadelsecure-cluster-dev --service citadelsecure-acme-frontend --desired-count 0
aws ecs update-service --cluster citadelsecure-cluster-dev --service citadelsecure-acme-backend --desired-count 0
aws ecs update-service --cluster citadelsecure-cluster-dev --service citadelsecure-router --desired-count 0

# To restart
aws ecs update-service --cluster citadelsecure-cluster-dev --service citadelsecure-acme-frontend --desired-count 1
aws ecs update-service --cluster citadelsecure-cluster-dev --service citadelsecure-acme-backend --desired-count 1
aws ecs update-service --cluster citadelsecure-cluster-dev --service citadelsecure-router --desired-count 1
```

**Full teardown** (preserves ECR images):
```bash
cd infrastructure/terraform/environments/dev
~/bin/terraform.exe state rm module.ecr  # Keep ECR
~/bin/terraform.exe destroy
```

---

## Tech Stack

| Layer | Technology | Local Dev | AWS |
|-------|------------|-----------|-----|
| Frontend | SvelteKit 2.x + Skeleton UI | Docker (port 3000) | ECS Fargate (port 3000) |
| Backend | Django 5.2.7 + DRF 3.15.2 | Docker (port 8000) | ECS Fargate (port 8000) |
| Database | PostgreSQL | 15-alpine | RDS 15.8 |
| Cache | Redis | 7-alpine | ElastiCache 7.0 |
| Storage | Object Storage | MinIO | S3 |
| Email | Email Service | MailHog (port 8025) | SES |
| Routing | Load Balancer | Nginx (port 80/443) | ALB + ACM |

**Version Note**: Local Docker uses `postgres:15-alpine` and `redis:7-alpine`. AWS uses RDS PostgreSQL 15.8 and ElastiCache Redis 7.0. These are compatible (same major versions).

---

## Database Architecture

| Container | External Port | Database | Purpose |
|-----------|---------------|----------|---------|
| postgres-metadata | 5432 | ciso_assistant | CustomerDomain routing ONLY |
| acme-db | 5433 | acme_db | Acme customer data (authoritative) |
| techstart-db | 5434 | techstart_db | TechStart customer data |
| medcorp-db | 5435 | medcorp_db | MedCorp customer data |

**Important**: Router authenticates against individual customer DBs, NOT postgres-metadata.

---

## Starting the Environment

```bash
# Start all services (SSR isolated stacks)
docker-compose -f docker-compose.isolated-stacks-ssr.yml up -d

# Check services are running
docker-compose -f docker-compose.isolated-stacks-ssr.yml ps

# View logs
docker logs citadel-router --tail 50
docker logs citadel-acme-frontend --tail 50
docker logs citadel-nginx --tail 50
```

**Required hosts file entries** (C:\Windows\System32\drivers\etc\hosts):
```
127.0.0.1 login.local
127.0.0.1 acme.local
127.0.0.1 techstart.local
127.0.0.1 medcorp.local
```

---

## Login Flow (Working as of Session 20)

1. Navigate to `http://login.local/login`
2. Enter email (e.g., `alice@acme.com`) and password
3. Router extracts customer from email domain → queries CustomerDomain table
4. Router authenticates against correct customer DB (acme-db)
5. Router generates JWT, redirects to `http://acme.local/api/iam/auth/complete/?token=...`
6. Backend validates JWT, creates Knox token, redirects to `/sso/authenticate/[knox_token]`
7. Frontend SSO endpoint sets cookies, redirects to dashboard

**Multi-account users**: If email has access to multiple customers, account selector is shown.

---

## Test Accounts

| Customer | Email | Password | DB Container |
|----------|-------|----------|--------------|
| Acme | alice@acme.com | AcmeTest123! | acme-db |
| Acme | bob@acme.com | AcmeTest123! | acme-db |
| TechStart | carol@techstart.io | TechStartTest123! | techstart-db |
| TechStart | david@techstart.io | TechStartTest123! | techstart-db |
| MedCorp | emma@medcorp.com | MedCorpTest123! | medcorp-db |
| MedCorp | frank@medcorp.com | MedCorpTest123! | medcorp-db |

**Login URL**: http://login.local/login

---

## Current Status (Session 32)

### Working ✅
- Centralized login (all 6 test users)
- Multi-account external user login
- SSR frontend rendering
- API endpoints (GET, POST, PUT, PATCH, DELETE)
- Session cookies (fixed secure flag issue)
- AWS deployment (ECS Fargate)
- Write operations in AWS (fixed handleFetch issue - Session 32)

### Known Issues
- PDF generation disabled (WeasyPrint on Windows)

---

## HTTPS (Local Development)

**Setup**: mkcert for trusted local certificates
```bash
mkcert -install
mkcert login.local acme.local techstart.local medcorp.local
# Creates login.local+3.pem and login.local+3-key.pem
```

**Nginx**: Configured in `nginx/isolated-stacks-ssr.conf` with SSL on port 443
**Cookies**: `secure: true` automatically when `ORIGIN` starts with `https://`

---

## Quick Verification Commands

```bash
# Check all containers running
docker-compose -f docker-compose.isolated-stacks-ssr.yml ps

# Test router login endpoint
curl -s -X POST http://login.local/auth/centralized-login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@acme.com", "password": "AcmeTest123!"}'

# Check router logs for auth
docker logs citadel-router --tail 20 | grep -E "(Authenticating|POST)"

# Verify user in correct DB
docker exec citadel-acme-db psql -U ciso_user -d acme_db -t -c \
  "SELECT id, email FROM iam_user WHERE email='alice@acme.com';"

# Restart nginx after container rebuilds (clears DNS cache)
docker restart citadel-nginx

# Rebuild specific containers
docker-compose -f docker-compose.isolated-stacks-ssr.yml build --no-cache \
  acme-frontend techstart-frontend medcorp-frontend

# Check ORIGIN env var in container
MSYS_NO_PATHCONV=1 docker exec citadel-acme-frontend printenv | grep ORIGIN
```

---

## Key Files

| File | Purpose |
|------|---------|
| `docker-compose.isolated-stacks-ssr.yml` | Current infrastructure definition |
| `nginx/isolated-stacks-ssr.conf` | Subdomain routing config |
| `router-service/app.py` | Centralized login logic |
| `backend/iam/sso/views.py` | AuthCompleteView (JWT validation) |
| `frontend/src/routes/(authentication)/sso/authenticate/[token]/+page.server.ts` | SSO cookie handling |

---

## Environment Notes

- **OS**: Windows 10/11 with Git Bash (NOT WSL2)
- **Paths**: Use `/d/...` or `D:\...` (not `/mnt/d/...`)
- **Docker**: Docker Desktop runs on Windows, interact via Git Bash
- **MSYS_NO_PATHCONV=1**: Required for docker exec commands with paths

---

## Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| 502 Bad Gateway | nginx cached old container IPs | `docker restart citadel-nginx` |
| "User not found" | Router querying wrong DB | Check CUSTOMER_DB_HOSTS in router |
| Cookies not setting | `secure: true` over HTTP | Fixed in Session 20 (ORIGIN-based check) |
| Login redirects to login | Cookie not persisted | Check browser dev tools, verify ORIGIN env |

---

*For detailed history, see DEVELOPMENT_LOG.md Sessions 14-20*
