from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI(title="Smart Contract Auditor AI", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
@app.get("/")
def root():
    return {"system": "Smart Contract Auditor AI", "version": "1.0.0", "status": "operational", "author": "Garrett Carrol", "organization": "Garcar Enterprise", "revenue_target": "$25K/month", "capabilities": ["vulnerability-detection", "reentrancy-analysis", "overflow-check", "access-control-audit", "gas-optimization"], "pricing": {"basic": "$99/month", "pro": "$299/month", "enterprise": "$999/month"}}
@app.get("/health")
def health():
    return {"status": "healthy", "system": "Smart Contract Auditor AI"}
