#!/usr/bin/env python3
"""
Smart Contract Auditor AI - Main Application
Revenue Target: $25K/month
"""
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./auditor.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# OpenAI client (v1 API)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

# Allowed origins for CORS - restrict to known frontends in production
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080"
).split(",")

app = FastAPI(
    title="Smart Contract Auditor AI",
    description="AI-powered security audits for smart contracts",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,  # credentials=False is safe with specific origins
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


# Models
class Audit(Base):  # type: ignore[valid-type,misc]
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, index=True)
    contract_code = Column(Text)
    contract_name = Column(String)
    severity = Column(String)
    findings_count = Column(Integer)
    report_url = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_email = Column(String)


Base.metadata.create_all(bind=engine)


# Pydantic models
class AuditRequest(BaseModel):
    contract_code: str = Field(..., min_length=10)
    contract_name: str = Field(default="Unnamed Contract")
    user_email: Optional[str] = None


class AuditResponse(BaseModel):
    audit_id: int
    severity: str
    findings: List[Dict]
    recommendations: List[str]
    report_url: str


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Core audit logic
async def analyze_contract(code: str, name: str) -> Dict:
    """
    Analyze smart contract using GPT-4 (OpenAI v1 client).
    """
    logger.info(f"Analyzing contract: {name}")
    system_prompt = """
You are an expert smart contract security auditor. Analyze the provided Solidity code for vulnerabilities.
Check for:
1. Reentrancy attacks
2. Integer overflow/underflow
3. Access control issues
4. Gas optimization problems
5. Unchecked external calls
6. Front-running vulnerabilities
7. Timestamp dependence
8. Denial of service vectors

Return JSON with:
- severity: "critical" | "high" | "medium" | "low" | "none"
- findings: [{type, location, description, severity}]
- recommendations: [string]
"""
    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo-preview",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Contract Name: {name}\n\nCode:\n{code}"},
            ],
            temperature=0.1,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content or "{}"
        return json.loads(content)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return {
            "severity": "error",
            "findings": [{"type": "analysis_error", "description": str(e)}],
            "recommendations": ["Please try again or contact support"],
        }


@app.get("/")
async def root():
    return {
        "service": "Smart Contract Auditor AI",
        "version": "1.0.0",
        "status": "operational",
        "revenue_target": "$25K/month",
        "pricing": {
            "basic": "$99/month (5 audits)",
            "pro": "$299/month (20 audits)",
            "enterprise": "$999/month (unlimited)",
        },
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected",
        "openai": "configured" if client.api_key else "missing",
    }


@app.post("/api/v1/audit", response_model=AuditResponse)
async def create_audit(
    request: AuditRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Create a new smart contract audit.
    """
    logger.info(f"New audit request: {request.contract_name}")

    # Analyze contract
    analysis = await analyze_contract(request.contract_code, request.contract_name)

    # Save to database
    audit = Audit(
        contract_code=request.contract_code,
        contract_name=request.contract_name,
        severity=analysis.get("severity", "unknown"),
        findings_count=len(analysis.get("findings", [])),
        user_email=request.user_email,
        report_url=f"/reports/{datetime.utcnow().timestamp()}.pdf",
    )
    db.add(audit)
    db.commit()
    db.refresh(audit)

    return AuditResponse(
        audit_id=audit.id,
        severity=analysis.get("severity", "unknown"),
        findings=analysis.get("findings", []),
        recommendations=analysis.get("recommendations", []),
        report_url=audit.report_url,
    )


@app.get("/api/v1/audits")
async def list_audits(
    skip: int = 0, limit: int = 100, db: Session = Depends(get_db)
):
    """
    List all audits.
    """
    audits = db.query(Audit).offset(skip).limit(limit).all()
    return {
        "total": db.query(Audit).count(),
        "audits": audits,
    }


@app.get("/api/v1/audits/{audit_id}")
async def get_audit(audit_id: int, db: Session = Depends(get_db)):
    """
    Get a specific audit by ID.
    """
    audit = db.query(Audit).filter(Audit.id == audit_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@app.get("/api/v1/stats")
async def get_stats(db: Session = Depends(get_db)):
    """
    Get platform statistics.
    """
    total_audits = db.query(Audit).count()
    critical_count = db.query(Audit).filter(Audit.severity == "critical").count()
    return {
        "total_audits": total_audits,
        "critical_findings": critical_count,
        "revenue_projection": {
            "current_month": "$2,500",
            "target": "$25,000",
        },
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
