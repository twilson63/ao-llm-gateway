# AO LLM Gateway

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/twilson63/ao-llm-gateway)

A self-hosted LLM gateway for AO (Actor Oriented) processes. Verify HyperBEAM-signed requests and route to OpenAI, Anthropic, Ollama, and other LLM providers.

## Features

- 🔐 **HyperBEAM Authentication** - Verify AO process identity via RFC-9421 HTTPSig signatures
- 🤖 **Multi-Provider Support** - OpenAI, Anthropic, Ollama, OpenRouter, custom providers
- 📊 **Admin Dashboard** - Jinja2 + HTMX for provider management
- 🚦 **Rate Limiting** - LMDB-based per-process limits (no Redis needed - truly open source)
- 🔒 **Secure** - API keys encrypted at rest, HTTPSig verification, rate limiting
- 🐳 **Docker Ready** - Production-ready containerized deployment

## Quick Start

### One-Click Deploy

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/twilson63/ao-llm_gateway)

[![Deploy to Railway](https://railway.app/button.svg)](https://railway.app/template)

### Manual Deploy

1. Clone the repository
2. Configure environment variables
3. Deploy with Docker

```bash
# Clone
git clone https://github.com/twilson63/ao-llm-gateway.git
cd ao-llm-gateway

# Configure
cp .env.example .env
# Edit .env with your settings

# Deploy
docker-compose up -d
```

## Usage

### Admin Dashboard

Access the admin panel at `http://localhost:8000/admin`

Default credentials:
- Email: `admin@example.com`
- Password: `admin` (change this!)

### Configure Providers

1. Login to admin dashboard
2. Click "+ Add Provider"
3. Configure:
   - Name: `openai`
   - Base URL: `https://api.openai.com`
   - Auth Type: `Bearer Token`
   - API Key: Your OpenAI API key
4. Save

### AO Process Access

Your HyperBEAM-powered AO agent can now call the gateway:

```curl
curl -X POST https://your-gateway.com/openai/gpt-4/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-HyperBEAM-Process-ID: jHkj8..." \
  -H "X-HyperBEAM-Authority: Uedrr7..." \
  -H "X-HyperBEAM-Signature: base64(...)" \
  -H "X-HyperBEAM-Timestamp: 2026-02-21T12:00:00Z" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Architecture

```
AO Process → HTTPSig Verification → Rate Limiting → Provider → LLM
     ↓              ↓                      ↓              ↓
Headers        Middleware            LMDB Store    OpenAI/etc
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_EMAIL` | Admin email | `admin@example.com` |
| `ADMIN_PASSWORD` | Admin password | `admin` |
| `DATABASE_URL` | SQLite/Postgres URL | `sqlite:///data/app.db` |
| `SECRET_KEY` | JWT signing key | auto-generated |
| `ENCRYPTION_KEY` | Fernet key for API encryption | auto-generated |
| `LMDB_PATH` | Rate limiting DB | `./data/ratelimit.db` |

## License

MIT - Open Source

## Why LMDB vs Redis?

- ✅ LMDB: OpenLDAP license (truly open source, BSD-like)
- ❌ Redis: SSPL (not OSI-approved, license changed 2024)

## Support

- GitHub Issues: [twilson63/ao-llm-gateway](https://github.com/twilson63/ao-llm-gateway)
- Docs: See PLAN.md for architecture details

Lets go
