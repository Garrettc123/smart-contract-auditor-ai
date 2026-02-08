#!/usr/bin/env python3
"""
Smart Contract Auditor AI
AI-powered vulnerability detection for Solidity smart contracts
Revenue Target: $25K/month
"""

import os
import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from fastapi import FastAPI, HTTPException, File, UploadFile, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
import openai
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import stripe

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Smart Contract Auditor AI",
    description="AI-powered smart contract vulnerability detection",
    version="1.0.0"
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
openai.api_key = os.getenv("OPENAI_API_KEY", "")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")

# OWASP Smart Contract Top 10
OWASP_VULNERABILITIES = [
    "Reentrancy",
    "Access Control",
    "Arithmetic Issues",
    "Unchecked Return Values",
    "Denial of Service",
    "Bad Randomness",
    "Front-Running",
    "Time Manipulation",
    "Short Address Attack",
    "Unknown Unknowns"
]


@dataclass
class Vulnerability:
    """Vulnerability finding"""
    severity: str  # critical, high, medium, low, info
    category: str
    line_number: Optional[int]
    code_snippet: str
    description: str
    recommendation: str
    confidence: float


class AuditRequest(BaseModel):
    """Audit request model"""
    contract_code: str = Field(..., description="Solidity contract code")
    contract_name: Optional[str] = Field(None, description="Contract name")
    version: Optional[str] = Field("0.8.0", description="Solidity version")


class AuditResponse(BaseModel):
    """Audit response model"""
    audit_id: str
    contract_name: str
    timestamp: str
    vulnerabilities: List[Dict[str, Any]]
    risk_score: float
    summary: Dict[str, int]
    recommendations: List[str]


class SmartContractAuditor:
    """AI-powered smart contract auditor"""
    
    def __init__(self):
        self.audits_performed = 0
        self.vulnerabilities_found = 0
        
    async def analyze_contract(self, code: str, contract_name: str = "Contract") -> Dict[str, Any]:
        """Analyze smart contract for vulnerabilities"""
        logger.info(f"Analyzing contract: {contract_name}")
        
        vulnerabilities = []
        
        # 1. Static analysis (basic pattern matching)
        static_vulns = self._static_analysis(code)
        vulnerabilities.extend(static_vulns)
        
        # 2. AI-powered analysis using GPT-4
        ai_vulns = await self._ai_analysis(code, contract_name)
        vulnerabilities.extend(ai_vulns)
        
        # 3. OWASP Top 10 check
        owasp_vulns = self._owasp_analysis(code)
        vulnerabilities.extend(owasp_vulns)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Generate summary
        summary = self._generate_summary(vulnerabilities)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(vulnerabilities)
        
        self.audits_performed += 1
        self.vulnerabilities_found += len(vulnerabilities)
        
        return {
            "audit_id": self._generate_audit_id(code),
            "contract_name": contract_name,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [self._vulnerability_to_dict(v) for v in vulnerabilities],
            "risk_score": risk_score,
            "summary": summary,
            "recommendations": recommendations
        }
    
    def _static_analysis(self, code: str) -> List[Vulnerability]:
        """Basic static analysis"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for reentrancy patterns
            if 'call.value' in line or 'send(' in line:
                vulnerabilities.append(Vulnerability(
                    severity="high",
                    category="Reentrancy",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="Potential reentrancy vulnerability detected. External calls should be made after state changes.",
                    recommendation="Use the Checks-Effects-Interactions pattern. Update state variables before making external calls.",
                    confidence=0.7
                ))
            
            # Check for unchecked external calls
            if '.call(' in line and 'require(' not in line and 'assert(' not in line:
                vulnerabilities.append(Vulnerability(
                    severity="medium",
                    category="Unchecked Return Values",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="External call without checking return value.",
                    recommendation="Always check return values from external calls using require() or assert().",
                    confidence=0.8
                ))
            
            # Check for timestamp dependence
            if 'block.timestamp' in line or 'now' in line:
                vulnerabilities.append(Vulnerability(
                    severity="low",
                    category="Time Manipulation",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="Contract relies on block.timestamp which can be manipulated by miners.",
                    recommendation="Avoid using block.timestamp for critical logic. Use block numbers or oracles if needed.",
                    confidence=0.6
                ))
            
            # Check for tx.origin usage
            if 'tx.origin' in line:
                vulnerabilities.append(Vulnerability(
                    severity="high",
                    category="Access Control",
                    line_number=i,
                    code_snippet=line.strip(),
                    description="Use of tx.origin for authentication is vulnerable to phishing attacks.",
                    recommendation="Use msg.sender instead of tx.origin for authentication.",
                    confidence=0.9
                ))
        
        return vulnerabilities
    
    async def _ai_analysis(self, code: str, contract_name: str) -> List[Vulnerability]:
        """AI-powered analysis using GPT-4"""
        if not openai.api_key:
            logger.warning("OpenAI API key not configured")
            return []
        
        try:
            prompt = f"""
You are an expert smart contract security auditor. Analyze the following Solidity contract for vulnerabilities.

Contract Name: {contract_name}

Contract Code:
```solidity
{code}
```

Provide a detailed security analysis covering:
1. Potential vulnerabilities (reentrancy, access control, arithmetic, etc.)
2. Severity level (critical/high/medium/low/info)
3. Specific line numbers if possible
4. Recommendations for fixes

Format your response as a JSON array of vulnerability objects:
[
  {{
    "severity": "high",
    "category": "Reentrancy",
    "line_number": 42,
    "description": "...",
    "recommendation": "..."
  }}
]
"""
            
            response = await asyncio.to_thread(
                openai.ChatCompletion.create,
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert smart contract security auditor."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )
            
            content = response.choices[0].message.content
            
            # Extract JSON from response
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            elif '```' in content:
                content = content.split('```')[1].split('```')[0].strip()
            
            vulns_data = json.loads(content)
            
            vulnerabilities = []
            for v in vulns_data:
                vulnerabilities.append(Vulnerability(
                    severity=v.get('severity', 'medium'),
                    category=v.get('category', 'Unknown'),
                    line_number=v.get('line_number'),
                    code_snippet=v.get('code_snippet', ''),
                    description=v.get('description', ''),
                    recommendation=v.get('recommendation', ''),
                    confidence=0.85
                ))
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return []
    
    def _owasp_analysis(self, code: str) -> List[Vulnerability]:
        """Check against OWASP Top 10"""
        vulnerabilities = []
        
        # Check for common OWASP patterns
        if 'delegatecall' in code:
            vulnerabilities.append(Vulnerability(
                severity="critical",
                category="Access Control",
                line_number=None,
                code_snippet="delegatecall usage detected",
                description="delegatecall can be dangerous if not properly restricted. It executes code in the context of the calling contract.",
                recommendation="Ensure delegatecall is only used with trusted contracts and proper access controls.",
                confidence=0.8
            ))
        
        if 'selfdestruct' in code:
            vulnerabilities.append(Vulnerability(
                severity="high",
                category="Access Control",
                line_number=None,
                code_snippet="selfdestruct usage detected",
                description="selfdestruct can permanently destroy the contract. Ensure proper access controls.",
                recommendation="Implement multi-sig or time-lock before allowing contract destruction.",
                confidence=0.9
            ))
        
        return vulnerabilities
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0.0
        
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }
        
        total_score = sum(
            severity_weights.get(v.severity, 5) * v.confidence
            for v in vulnerabilities
        )
        
        # Normalize to 0-100
        return min(100.0, total_score)
    
    def _generate_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Generate vulnerability summary"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for v in vulnerabilities:
            summary[v.severity] = summary.get(v.severity, 0) + 1
        
        return summary
    
    def _generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Generate top recommendations"""
        recommendations = []
        
        # Get unique recommendations
        seen = set()
        for v in sorted(vulnerabilities, key=lambda x: x.severity):
            if v.recommendation and v.recommendation not in seen:
                recommendations.append(v.recommendation)
                seen.add(v.recommendation)
        
        return recommendations[:10]  # Top 10
    
    def _vulnerability_to_dict(self, v: Vulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dict"""
        return {
            'severity': v.severity,
            'category': v.category,
            'line_number': v.line_number,
            'code_snippet': v.code_snippet,
            'description': v.description,
            'recommendation': v.recommendation,
            'confidence': v.confidence
        }
    
    def _generate_audit_id(self, code: str) -> str:
        """Generate unique audit ID"""
        hash_obj = hashlib.sha256(code.encode())
        return f"audit_{hash_obj.hexdigest()[:16]}"


# Initialize auditor
auditor = SmartContractAuditor()


# API Key validation
async def verify_api_key(x_api_key: str = Header(...)):
    """Verify API key"""
    valid_keys = os.getenv("API_KEYS", "").split(",")
    if x_api_key not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Smart Contract Auditor AI",
        "version": "1.0.0",
        "status": "operational",
        "audits_performed": auditor.audits_performed,
        "vulnerabilities_found": auditor.vulnerabilities_found
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "openai_configured": bool(openai.api_key),
        "stripe_configured": bool(stripe.api_key)
    }


@app.post("/api/v1/audit", response_model=AuditResponse)
@limiter.limit("10/minute")
async def audit_contract(
    request: AuditRequest,
    api_key: str = Depends(verify_api_key)
):
    """Audit a smart contract"""
    try:
        result = await auditor.analyze_contract(
            code=request.contract_code,
            contract_name=request.contract_name or "Contract"
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/audit/file")
@limiter.limit("5/minute")
async def audit_file(
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key)
):
    """Audit a contract from uploaded file"""
    try:
        content = await file.read()
        code = content.decode('utf-8')
        
        result = await auditor.analyze_contract(
            code=code,
            contract_name=file.filename or "Contract"
        )
        return JSONResponse(content=result)
    except Exception as e:
        logger.error(f"File audit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats")
async def get_stats():
    """Get service statistics"""
    return {
        "audits_performed": auditor.audits_performed,
        "vulnerabilities_found": auditor.vulnerabilities_found,
        "avg_vulnerabilities_per_audit": (
            auditor.vulnerabilities_found / auditor.audits_performed
            if auditor.audits_performed > 0 else 0
        )
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
