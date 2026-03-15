"""
Tests for Module 1: Input Layer
"""
import pytest
from app.core.input_layer import ScopeFilter, TargetIngestion, get_root_domain


class TestScopeFilter:

    def test_wildcard_in_scope(self):
        scope = ScopeFilter(in_scope=["*.example.com"])
        assert scope.is_in_scope("api.example.com") is True
        assert scope.is_in_scope("deep.sub.example.com") is True

    def test_out_of_scope_filtered(self):
        scope = ScopeFilter(in_scope=["*.example.com"], out_of_scope=["excluded.example.com"])
        assert scope.is_in_scope("excluded.example.com") is False
        assert scope.is_in_scope("api.example.com") is True

    def test_different_domain_out_of_scope(self):
        scope = ScopeFilter(in_scope=["*.example.com"])
        assert scope.is_in_scope("evil.com") is False

    def test_filter_list(self):
        scope = ScopeFilter(in_scope=["*.example.com"])
        targets = ["api.example.com", "evil.com", "admin.example.com"]
        filtered = scope.filter(targets)
        assert "api.example.com" in filtered
        assert "evil.com" not in filtered

    def test_exact_domain(self):
        scope = ScopeFilter(in_scope=["example.com"])
        assert scope.is_in_scope("example.com") is True


class TestTargetIngestion:

    def test_from_string_single(self):
        ingestion = TargetIngestion()
        targets = ingestion.from_string("example.com")
        assert "example.com" in targets

    def test_from_string_multiple(self):
        ingestion = TargetIngestion()
        targets = ingestion.from_string("example.com, test.org")
        assert len(targets) == 2

    def test_invalid_domain_removed(self):
        ingestion = TargetIngestion()
        targets = ingestion.from_string("not-a-valid-!!!domain")
        assert len(targets) == 0


class TestSecretEngine:

    def test_aws_key_detection(self):
        from app.core.secret_engine import SecretEngine
        engine = SecretEngine()
        text = 'access_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = engine.scan_text(text, "https://example.com/app.js")
        secret_types = [f["type"] for f in findings]
        assert "AWS Access Key" in secret_types

    def test_jwt_detection(self):
        from app.core.secret_engine import SecretEngine
        engine = SecretEngine()
        text = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        findings = engine.scan_text(text, "test.js")
        assert any("JWT" in f["type"] for f in findings)

    def test_entropy_calculation(self):
        from app.core.secret_engine import shannon_entropy
        # High entropy random string
        assert shannon_entropy("aB3$rTy9!qZ5mX2@pL7n") > 3.5
        # Low entropy
        assert shannon_entropy("aaaaaaaaaaaaaaaaaa") < 1.0
