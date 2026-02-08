# Smart Contract Auditor AI

> AI-powered vulnerability detection for Solidity smart contracts  
> **Revenue Target**: $25K/month

## Features

- 🔍 **Static Analysis** - Pattern matching for common vulnerabilities
- 🤖 **AI-Powered Analysis** - GPT-4 deep code review
- 📋 **OWASP Top 10** - Checks against OWASP Smart Contract Top 10
- 📊 **Risk Scoring** - Quantified security score (0-100)
- 📄 **Detailed Reports** - Line-by-line vulnerability breakdown
- ⚡ **Fast** - Results in seconds
- 🔒 **Secure** - API key authentication + rate limiting

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/Garrettc123/smart-contract-auditor-ai.git
cd smart-contract-auditor-ai

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### 2. Run Locally

```bash
python app.py
```

Service runs on `http://localhost:8000`

### 3. Deploy to Railway

```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Deploy
railway up
```

## API Usage

### Audit Contract Code

```bash
curl -X POST "https://your-app.railway.app/api/v1/audit" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "contract_code": "pragma solidity ^0.8.0; contract Test { ... }",
    "contract_name": "MyContract"
  }'
```

### Audit Contract File

```bash
curl -X POST "https://your-app.railway.app/api/v1/audit/file" \
  -H "X-API-Key: your-api-key" \
  -F "file=@MyContract.sol"
```

## Response Format

```json
{
  "audit_id": "audit_abc123...",
  "contract_name": "MyContract",
  "timestamp": "2026-02-08T14:30:00",
  "vulnerabilities": [
    {
      "severity": "high",
      "category": "Reentrancy",
      "line_number": 42,
      "code_snippet": "address.call.value(amount)();",
      "description": "Potential reentrancy vulnerability...",
      "recommendation": "Use Checks-Effects-Interactions pattern...",
      "confidence": 0.9
    }
  ],
  "risk_score": 75.5,
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3,
    "info": 1
  },
  "recommendations": [
    "Use Checks-Effects-Interactions pattern",
    "Always check return values from external calls"
  ]
}
```

## Vulnerability Categories

1. **Reentrancy** - External call vulnerabilities
2. **Access Control** - Authentication/authorization issues
3. **Arithmetic Issues** - Overflow/underflow
4. **Unchecked Return Values** - Ignored call results
5. **Denial of Service** - Gas limit attacks
6. **Bad Randomness** - Predictable random numbers
7. **Front-Running** - Transaction ordering attacks
8. **Time Manipulation** - Block timestamp dependence
9. **Short Address Attack** - Input validation
10. **Unknown Unknowns** - Novel vulnerabilities

## Pricing

| Plan | Price | Audits/Month | Support |
|------|-------|--------------|----------|
| Basic | $99/mo | 5 | Email |
| Pro | $299/mo | 20 | Priority Email |
| Enterprise | $999/mo | Unlimited | Slack + Phone |

## Revenue Model

- **Target**: $25K/month
- **Pricing**: $99 - $999/month subscriptions
- **Market**: 50,000+ deployed smart contracts
- **Conversion**: 15% trial-to-paid

## Tech Stack

- **Backend**: Python 3.11 + FastAPI
- **AI**: OpenAI GPT-4
- **Payments**: Stripe
- **Deployment**: Railway/Render
- **Database**: SQLite (logs)

## Security

- ✅ API key authentication
- ✅ Rate limiting (10 req/min)
- ✅ Input validation
- ✅ HTTPS only
- ✅ CORS protection

## Roadmap

- [ ] Week 1: MVP launch
- [ ] Week 2: GitHub integration
- [ ] Week 3: PDF report generation
- [ ] Week 4: Subscription billing
- [ ] Month 2: Multi-language support (Rust, Move)
- [ ] Month 3: CI/CD pipeline integration

## License

MIT License - See LICENSE file

## Contact

- Website: [smart-contract-auditor.ai](https://smart-contract-auditor.ai)
- Email: support@garcar-enterprise.com
- Twitter: [@GarcarEnterprise](https://twitter.com/GarcarEnterprise)
