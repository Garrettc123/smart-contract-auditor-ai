"""Tests for Smart Contract Auditor AI."""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main import app, AuditRequest, AuditResponse, analyze_contract


client = TestClient(app)


class TestRootEndpoint:
    """Tests for the root endpoint."""

    def test_root_returns_200(self):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_contains_service_name(self):
        response = client.get("/")
        data = response.json()
        assert data["service"] == "Smart Contract Auditor AI"
        assert data["status"] == "operational"
        assert "pricing" in data

    def test_root_contains_pricing(self):
        response = client.get("/")
        data = response.json()
        assert "basic" in data["pricing"]
        assert "pro" in data["pricing"]
        assert "enterprise" in data["pricing"]


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_status(self):
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "database" in data
        assert "openai" in data


class TestAuditRequest:
    """Tests for AuditRequest Pydantic model."""

    def test_valid_request(self):
        req = AuditRequest(
            contract_code="pragma solidity ^0.8.0; contract Test {}",
            contract_name="Test Contract",
        )
        assert req.contract_name == "Test Contract"
        assert len(req.contract_code) >= 10

    def test_default_contract_name(self):
        req = AuditRequest(contract_code="pragma solidity ^0.8.0; contract Test {}")
        assert req.contract_name == "Unnamed Contract"

    def test_short_code_rejected(self):
        with pytest.raises(Exception):
            AuditRequest(contract_code="short")


class TestStatsEndpoint:
    """Tests for the stats endpoint."""

    def test_stats_returns_200(self):
        response = client.get("/api/v1/stats")
        assert response.status_code == 200

    def test_stats_structure(self):
        response = client.get("/api/v1/stats")
        data = response.json()
        assert "total_audits" in data
        assert "critical_findings" in data
        assert "revenue_projection" in data


class TestListAudits:
    """Tests for the list audits endpoint."""

    def test_list_audits_returns_200(self):
        response = client.get("/api/v1/audits")
        assert response.status_code == 200

    def test_list_audits_structure(self):
        response = client.get("/api/v1/audits")
        data = response.json()
        assert "total" in data
        assert "audits" in data
        assert isinstance(data["audits"], list)


class TestGetAuditNotFound:
    """Tests for the get audit by ID endpoint (not found case)."""

    def test_get_nonexistent_audit(self):
        response = client.get("/api/v1/audits/99999")
        assert response.status_code == 404


class TestAnalyzeContract:
    """Tests for analyze_contract function."""

    @pytest.mark.asyncio
    async def test_analyze_contract_error_handling(self):
        """analyze_contract should return error dict on OpenAI failure."""
        with patch("src.main.client") as mock_client:
            mock_client.chat.completions.create.side_effect = Exception("API error")
            result = await analyze_contract("pragma solidity ^0.8.0;", "Test")
            assert result["severity"] == "error"
            assert len(result["findings"]) > 0
            assert len(result["recommendations"]) > 0

    @pytest.mark.asyncio
    async def test_analyze_contract_success(self):
        """analyze_contract should parse and return JSON from OpenAI."""
        mock_response = MagicMock()
        mock_response.choices[0].message.content = (
            '{"severity": "low", "findings": [], "recommendations": ["Use latest Solidity"]}'  # noqa: E501
        )
        with patch("src.main.client") as mock_client:
            mock_client.chat.completions.create.return_value = mock_response
            result = await analyze_contract("pragma solidity ^0.8.0;", "Test")
            assert result["severity"] == "low"
            assert isinstance(result["findings"], list)
            assert isinstance(result["recommendations"], list)
