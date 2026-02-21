from .base import BaseModule
import base64
import json
import logging
import os
import requests

logger = logging.getLogger("reqreaper")

# Algorithms considered weak or dangerous
WEAK_ALGORITHMS = {"none", "hs256", "hs1"}

REQUIRED_CLAIMS = {"exp", "aud", "iss"}


class JwtModule(BaseModule):
    def __init__(self, config, output_dir, db_path):
        super().__init__(config, output_dir, db_path)
        self.required_tool = None  # Native Python

    def run(self, targets):
        tokens = self._collect_tokens(targets)
        results = []

        for token, source in tokens:
            header, payload = self.decode_jwt(token)
            if header is None:
                logger.warning(f"[jwt] Could not decode token from {source}")
                continue

            findings = self._analyze(header, payload, source, token)
            results.extend(findings)

        self.parse_results(results)
        return results

    def _collect_tokens(self, targets):
        """Collect JWT tokens from config and by probing target responses."""
        tokens = []

        # 1. Tokens explicitly listed in config
        for token in self.config.get("jwt_tokens", []):
            tokens.append((token, "config"))

        # 2. Probe each target's response headers for Bearer tokens
        auth = self.config.get("auth", {})
        req_headers = {}
        if auth.get("header_name") and auth.get("header_value"):
            req_headers[auth["header_name"]] = auth["header_value"]
            # If the configured auth value itself is a Bearer JWT, capture it
            value = auth["header_value"]
            if value.lower().startswith("bearer "):
                candidate = value.split(" ", 1)[1].strip()
                if self._looks_like_jwt(candidate):
                    tokens.append((candidate, "auth_config"))

        timeout = self.config.get("timeout", 30)
        for target in targets:
            try:
                resp = requests.get(target, headers=req_headers, timeout=timeout, allow_redirects=True)
                # Check Authorization / WWW-Authenticate / Set-Cookie headers
                for header_name in ("Authorization", "X-Auth-Token", "X-Access-Token"):
                    val = resp.headers.get(header_name, "")
                    if val.lower().startswith("bearer "):
                        candidate = val.split(" ", 1)[1].strip()
                        if self._looks_like_jwt(candidate):
                            tokens.append((candidate, f"response_header:{header_name}@{target}"))
                # Check response body for JWT-shaped strings (simple heuristic)
                try:
                    body = resp.json()
                    self._extract_tokens_from_dict(body, target, tokens)
                except Exception:
                    pass
            except requests.RequestException as e:
                logger.debug(f"[jwt] Could not probe {target}: {e}")

        return tokens

    def _extract_tokens_from_dict(self, obj, source, tokens, depth=0):
        """Recursively search a dict/list for JWT-shaped strings."""
        if depth > 4:
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(val, str) and self._looks_like_jwt(val):
                    tokens.append((val, f"response_body:{key}@{source}"))
                else:
                    self._extract_tokens_from_dict(val, source, tokens, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_tokens_from_dict(item, source, tokens, depth + 1)

    def _looks_like_jwt(self, value):
        parts = value.split(".")
        return len(parts) == 3 and all(len(p) > 0 for p in parts)

    def decode_jwt(self, token):
        """Decode JWT header and payload without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None
            # Add padding
            header_b64 = parts[0] + "=="
            payload_b64 = parts[1] + "=="
            header = json.loads(base64.urlsafe_b64decode(header_b64).decode("utf-8"))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
            return header, payload
        except Exception:
            return None, None

    def _analyze(self, header, payload, source, token):
        """Check for common JWT vulnerabilities and misconfigurations."""
        findings = []
        alg = header.get("alg", "").lower()

        # 1. Algorithm: none
        if alg == "none":
            findings.append({
                "source": source,
                "issue": "Algorithm 'none' — no signature verification",
                "severity": "critical",
                "detail": "Token accepts unsigned payloads. Trivially forgeable.",
            })

        # 2. Weak algorithm
        elif alg in WEAK_ALGORITHMS:
            findings.append({
                "source": source,
                "issue": f"Weak algorithm: {header.get('alg')}",
                "severity": "medium",
                "detail": "Symmetric algorithms like HS256 are susceptible to brute-force if the secret is weak.",
            })

        # 3. Missing expiry
        if "exp" not in payload:
            findings.append({
                "source": source,
                "issue": "Missing 'exp' claim — token never expires",
                "severity": "high",
                "detail": "Tokens without expiry remain valid indefinitely if compromised.",
            })

        # 4. Missing audience
        if "aud" not in payload:
            findings.append({
                "source": source,
                "issue": "Missing 'aud' claim",
                "severity": "low",
                "detail": "Token can be replayed against any service that trusts the issuer.",
            })

        # 5. Missing issuer
        if "iss" not in payload:
            findings.append({
                "source": source,
                "issue": "Missing 'iss' claim",
                "severity": "low",
                "detail": "No issuer claim — origin of the token cannot be verified.",
            })

        return findings

    def parse_results(self, data):
        normalized = []
        for item in data:
            normalized.append({
                "tool": "jwt",
                "severity": item["severity"],
                "title": item["issue"],
                "endpoint": item["source"],
                "evidence_path": item.get("detail", ""),
                "confidence": "high",
            })

        self.findings_count = len(normalized)
        if self.dm and normalized:
            self.dm.add_data("findings", normalized)

        # Also write a local summary CSV for quick review
        if normalized:
            import csv
            csv_path = os.path.join(self.normalized_output_dir, "jwt_findings.csv")
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["tool", "severity", "title", "endpoint", "evidence_path", "confidence"])
                writer.writeheader()
                writer.writerows(normalized)
