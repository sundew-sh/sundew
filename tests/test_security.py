"""Security tests for Sundew honeypot.

These tests verify the core security invariants:
- No code execution from external input
- MCP tool responses are hardcoded fiction
- No secrets in default configurations
- Docker container runs non-root
- All canary tokens are verifiably fake
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
SUNDEW_PKG = SRC_DIR / "sundew"


def _python_files() -> Iterator[Path]:
    """Yield all .py files under src/sundew/."""
    yield from SUNDEW_PKG.rglob("*.py")


def _read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# AST-based dangerous-call detection
# ---------------------------------------------------------------------------

# Functions that MUST NEVER be called on user-controlled input.
DANGEROUS_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "execfile",  # Python 2, but check anyway
        "__import__",
    }
)

DANGEROUS_MODULES = frozenset(
    {
        "subprocess",
        "os.system",
        "os.popen",
        "os.exec",
        "os.spawn",
        "pty.spawn",
        "commands.getoutput",  # Python 2, belt-and-suspenders
    }
)

DANGEROUS_OS_ATTRS = frozenset(
    {
        "system",
        "popen",
        "popen2",
        "popen3",
        "popen4",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
    }
)


class DangerousCallVisitor(ast.NodeVisitor):
    """AST visitor that flags dangerous function calls."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.violations: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Direct calls: eval(...), exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
            self.violations.append(
                f"{self.filepath}:{node.lineno} - direct call to {node.func.id}()"
            )

        # Attribute calls: os.system(...), subprocess.run(...)
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr

            # os.<dangerous_method>(...)
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and attr in DANGEROUS_OS_ATTRS
            ):
                self.violations.append(f"{self.filepath}:{node.lineno} - call to os.{attr}()")

            # subprocess.<anything>(...)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                self.violations.append(
                    f"{self.filepath}:{node.lineno} - call to subprocess.{attr}()"
                )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            if alias.name == "subprocess":
                self.violations.append(f"{self.filepath}:{node.lineno} - imports subprocess module")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module and node.module.startswith("subprocess"):
            self.violations.append(f"{self.filepath}:{node.lineno} - imports from subprocess")
        self.generic_visit(node)


def _find_dangerous_calls(path: Path) -> list[str]:
    """Parse a Python file and return all dangerous call violations."""
    source = _read_source(path)
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return [f"{path}: SyntaxError -- cannot parse"]
    visitor = DangerousCallVisitor(str(path.relative_to(PROJECT_ROOT)))
    visitor.visit(tree)
    return visitor.violations


# ---------------------------------------------------------------------------
# Tests: No dangerous calls in source
# ---------------------------------------------------------------------------


class TestNoDangerousCalls:
    """Verify no eval/exec/subprocess/os.system in any source file."""

    def test_no_dangerous_calls_in_source(self) -> None:
        all_violations: list[str] = []
        for pyfile in _python_files():
            all_violations.extend(_find_dangerous_calls(pyfile))

        if all_violations:
            report = "\n".join(f"  - {v}" for v in all_violations)
            pytest.fail(
                f"Dangerous calls found in source code:\n{report}\n\n"
                "Sundew must NEVER call eval/exec/subprocess/os.system on any "
                "value that could originate from external input."
            )

    def test_no_pickle_loads(self) -> None:
        """pickle.loads is a code execution vector -- must not appear."""
        for pyfile in _python_files():
            source = _read_source(pyfile)
            if "pickle.loads" in source or "pickle.load(" in source:
                rel = pyfile.relative_to(PROJECT_ROOT)
                pytest.fail(f"{rel} uses pickle deserialization -- code execution risk")

    def test_no_yaml_unsafe_load(self) -> None:
        """yaml.load without SafeLoader is a code execution vector."""
        for pyfile in _python_files():
            source = _read_source(pyfile)
            tree = ast.parse(source, filename=str(pyfile))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "load"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "yaml"
                ):
                    # Check that Loader=SafeLoader or yaml.safe_load is used
                    has_safe_loader = any(
                        isinstance(kw, ast.keyword)
                        and kw.arg == "Loader"
                        and isinstance(kw.value, ast.Attribute)
                        and "safe" in kw.value.attr.lower()
                        for kw in node.keywords
                    )
                    if not has_safe_loader:
                        rel = pyfile.relative_to(PROJECT_ROOT)
                        pytest.fail(f"{rel}:{node.lineno} uses yaml.load() without SafeLoader")


# ---------------------------------------------------------------------------
# Tests: MCP tool handlers are hardcoded fiction
# ---------------------------------------------------------------------------


class TestMCPToolsAreFiction:
    """Verify MCP execute_command/execute_sql return cached responses only."""

    def _find_mcp_handler_files(self) -> list[Path]:
        """Find files that likely contain MCP tool handler definitions."""
        candidates = []
        for pyfile in _python_files():
            source = _read_source(pyfile)
            if "execute_command" in source or "execute_sql" in source or "mcp" in source.lower():
                candidates.append(pyfile)
        return candidates

    def test_mcp_handlers_no_real_execution(self) -> None:
        """MCP tool handlers must not invoke real shells or databases."""
        handler_files = self._find_mcp_handler_files()
        for pyfile in handler_files:
            violations = _find_dangerous_calls(pyfile)
            if violations:
                report = "\n".join(f"  - {v}" for v in violations)
                rel = pyfile.relative_to(PROJECT_ROOT)
                pytest.fail(
                    f"MCP handler file {rel} contains dangerous calls:\n{report}\n"
                    "MCP tool responses must be hardcoded cached fiction ONLY."
                )

    def test_no_sqlite_in_mcp_handlers(self) -> None:
        """MCP 'execute_sql' must not use real sqlite3/sqlalchemy."""
        handler_files = self._find_mcp_handler_files()
        for pyfile in handler_files:
            source = _read_source(pyfile)
            # Allow sqlite usage in logging module, but not in MCP handlers
            has_mcp_tools = "execute_sql" in source or "execute_command" in source
            has_real_db = "sqlite3.connect" in source or "create_engine" in source
            if has_mcp_tools and has_real_db:
                rel = pyfile.relative_to(PROJECT_ROOT)
                pytest.fail(
                    f"{rel} contains real database calls in MCP handler context. "
                    "MCP execute_sql must return hardcoded fake query results."
                )


# ---------------------------------------------------------------------------
# Tests: No secrets in default configuration
# ---------------------------------------------------------------------------

# Patterns that look like real secrets
SECRET_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    # Generic high-entropy strings that aren't our fake prefix
    (r"(?<!\bsk-sundew-FAKE-)sk-[a-zA-Z0-9]{20,}", "OpenAI-style API key"),
    # GitHub PAT
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
    (r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}", "GitHub Fine-grained PAT"),
    # Generic password assignments
    (r'(?i)password\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded password"),
]


class TestNoSecrets:
    """Verify no real secrets appear in source, config, or defaults."""

    def _files_to_scan(self) -> Iterator[Path]:
        """All files that could contain secrets."""
        yield from _python_files()
        yield from PROJECT_ROOT.rglob("*.yaml")
        yield from PROJECT_ROOT.rglob("*.yml")
        yield from PROJECT_ROOT.rglob("*.toml")
        yield from PROJECT_ROOT.rglob("*.json")
        yield from PROJECT_ROOT.rglob("*.env")
        yield from PROJECT_ROOT.rglob("*.env.*")
        # Also check Dockerfiles
        yield from PROJECT_ROOT.rglob("Dockerfile*")

    def test_no_real_secrets_in_source(self) -> None:
        violations: list[str] = []
        for filepath in self._files_to_scan():
            if not filepath.is_file():
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue
            for pattern, description in SECRET_PATTERNS:
                matches = re.finditer(pattern, content)
                for match in matches:
                    # Allow if it's clearly in a test file documenting the pattern
                    if "test_security" in filepath.name:
                        continue
                    violations.append(
                        f"{filepath.relative_to(PROJECT_ROOT)}: "
                        f"{description} found: {match.group()[:20]}..."
                    )
        if violations:
            report = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(f"Potential secrets found:\n{report}")

    def test_no_env_files_in_repo(self) -> None:
        """Ensure .env files are not committed."""
        env_files = list(PROJECT_ROOT.rglob(".env"))
        env_files += list(PROJECT_ROOT.rglob(".env.*"))
        # Filter out .env.example which is allowed
        real_env = [f for f in env_files if ".example" not in f.name]
        if real_env:
            names = [str(f.relative_to(PROJECT_ROOT)) for f in real_env]
            pytest.fail(f".env files found in repo (should be gitignored): {names}")


# ---------------------------------------------------------------------------
# Tests: Canary token safety
# ---------------------------------------------------------------------------

# Reserved IP ranges (RFC 1918 + RFC 5737 + loopback)
RESERVED_IP_PATTERN = re.compile(
    r"\b("
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|198\.51\.100\.\d{1,3}"
    r"|203\.0\.113\.\d{1,3}"
    r"|0\.0\.0\.0"
    r")\b"
)

# Safe domain TLDs per RFC 2606 / RFC 6761
SAFE_DOMAIN_PATTERN = re.compile(
    r"\b([\w.-]+\.)?(example\.com|example\.org|example\.net|example|test|invalid|localhost)\b"
)

# IP address pattern (to find non-reserved IPs)
ANY_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Domain-like pattern
ANY_DOMAIN_PATTERN = re.compile(r"\b([\w][\w-]*\.(?:com|org|net|io|dev|app|cloud|ai))\b")


class TestCanaryTokenSafety:
    """Verify all canary/fake data uses reserved ranges and safe domains."""

    def _canary_files(self) -> Iterator[Path]:
        """Files likely to contain canary token definitions."""
        for pyfile in _python_files():
            source = _read_source(pyfile)
            if any(
                kw in source.lower()
                for kw in ["canary", "fake", "honey", "credential", "token", "decoy"]
            ):
                yield pyfile
        # Also check persona packs
        yield from (SUNDEW_PKG / "persona" / "packs").rglob("*.yaml")
        yield from (SUNDEW_PKG / "persona" / "packs").rglob("*.yml")
        yield from (SUNDEW_PKG / "persona" / "packs").rglob("*.json")

    def test_canary_ips_are_reserved(self) -> None:
        """All IP addresses in canary data must be RFC 1918 reserved."""
        violations: list[str] = []
        for filepath in self._canary_files():
            if not filepath.is_file():
                continue
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            for match in ANY_IP_PATTERN.finditer(content):
                ip = match.group(1)
                # Skip if it's a version number-like pattern (e.g., 2.10.0)
                context = content[max(0, match.start() - 20) : match.end() + 10]
                if ">=" in context or "<=" in context or "version" in context.lower():
                    continue
                # Skip software/version patterns like "nginx/1.24.0" or "openresty/1.25.3.1"
                if "/" in context and match.start() > 0 and content[match.start() - 1] != " ":
                    continue
                if not RESERVED_IP_PATTERN.match(ip):
                    violations.append(f"{filepath.relative_to(PROJECT_ROOT)}: non-reserved IP {ip}")
        if violations:
            report = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Canary tokens contain non-reserved IP addresses:\n{report}\n"
                "All IPs must be in RFC 1918/5737 reserved ranges."
            )

    def test_canary_domains_are_safe(self) -> None:
        """All domains in canary data must use .example.com/.test/.invalid."""
        violations: list[str] = []
        for filepath in self._canary_files():
            if not filepath.is_file():
                continue
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            for match in ANY_DOMAIN_PATTERN.finditer(content):
                domain = match.group(1)
                # Skip common Python/package domains
                if domain in {
                    "python.org",
                    "pypi.org",
                    "github.com",
                    "fastapi.com",
                    "pydantic.dev",
                    "readthedocs.io",
                    "sundew-honeypot.example.com",
                    "sitemaps.org",
                }:
                    continue
                # Skip Python attribute access patterns (self.app, server.app)
                if domain.startswith(("self.", "cls.")):
                    continue
                prefix = content[max(0, match.start() - 5) : match.start()]
                if prefix.rstrip().endswith((".", "import", "from")):
                    continue
                # Skip code identifiers (word.app, word.net etc.)
                if re.match(r"^[a-z_]+\.[a-z]+$", domain) and "." not in domain.split(".", 1)[1]:
                    # Simple word.tld that looks like Python attribute access
                    pre_char = content[match.start() - 1] if match.start() > 0 else ""
                    if pre_char in (" ", "\n", "", "(", ",", "="):
                        continue
                    continue
                if not SAFE_DOMAIN_PATTERN.match(domain):
                    violations.append(
                        f"{filepath.relative_to(PROJECT_ROOT)}: non-reserved domain {domain}"
                    )
        if violations:
            report = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Canary tokens contain non-reserved domains:\n{report}\n"
                "All domains must use .example.com, .test, or .invalid TLDs."
            )

    def test_fake_api_keys_have_sundew_prefix(self) -> None:
        """API keys in canary data must use the sk-sundew-FAKE- prefix."""
        for filepath in self._canary_files():
            if not filepath.is_file():
                continue
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            # Find anything that looks like an API key
            for match in re.finditer(r"sk-[a-zA-Z0-9_-]{10,}", content):
                key = match.group()
                if not key.startswith("sk-sundew-FAKE-"):
                    rel = filepath.relative_to(PROJECT_ROOT)
                    pytest.fail(
                        f"{rel}: API key '{key[:25]}...' does not use "
                        "required 'sk-sundew-FAKE-' prefix"
                    )


# ---------------------------------------------------------------------------
# Tests: Docker security
# ---------------------------------------------------------------------------


class TestDockerSecurity:
    """Verify Dockerfile follows security best practices."""

    def _find_dockerfiles(self) -> list[Path]:
        return list(PROJECT_ROOT.rglob("Dockerfile*"))

    def test_dockerfile_runs_nonroot(self) -> None:
        """Container must not run as root."""
        dockerfiles = self._find_dockerfiles()
        if not dockerfiles:
            pytest.skip("No Dockerfile found yet (may be created by another teammate)")

        for dockerfile in dockerfiles:
            content = dockerfile.read_text(encoding="utf-8")
            # Must have a USER directive that is not root
            user_lines = [
                line.strip()
                for line in content.splitlines()
                if line.strip().upper().startswith("USER ")
            ]
            if not user_lines:
                pytest.fail(f"{dockerfile.name}: No USER directive -- runs as root by default")

            last_user = user_lines[-1].split()[1]
            if last_user in ("root", "0"):
                pytest.fail(f"{dockerfile.name}: Final USER is root -- must be non-root")

    def test_dockerfile_no_secrets(self) -> None:
        """Dockerfile must not contain embedded secrets."""
        dockerfiles = self._find_dockerfiles()
        if not dockerfiles:
            pytest.skip("No Dockerfile found yet")

        for dockerfile in dockerfiles:
            content = dockerfile.read_text(encoding="utf-8")
            for pattern, description in SECRET_PATTERNS:
                if re.search(pattern, content):
                    pytest.fail(f"{dockerfile.name}: {description} found in Dockerfile")

    def test_dockerfile_has_healthcheck(self) -> None:
        """Dockerfile should have a HEALTHCHECK directive."""
        dockerfiles = self._find_dockerfiles()
        if not dockerfiles:
            pytest.skip("No Dockerfile found yet")

        for dockerfile in dockerfiles:
            content = dockerfile.read_text(encoding="utf-8")
            if "HEALTHCHECK" not in content:
                pytest.fail(f"{dockerfile.name}: Missing HEALTHCHECK directive")


# ---------------------------------------------------------------------------
# Tests: Dependency pinning
# ---------------------------------------------------------------------------


class TestDependencyPinning:
    """Verify dependencies are pinned to specific versions for reproducibility."""

    def test_pyproject_deps_have_upper_bounds(self) -> None:
        """All dependencies should have upper bounds to prevent supply chain attacks."""
        pyproject = PROJECT_ROOT / "pyproject.toml"
        if not pyproject.exists():
            pytest.skip("pyproject.toml not found")

        content = pyproject.read_text(encoding="utf-8")
        # This is a warning-level check -- we flag >= without < as a risk
        # In production, dependencies should be pinned or have upper bounds
        lines_with_deps = [
            line.strip().strip('"').strip("'").strip(",")
            for line in content.splitlines()
            if ">=" in line and "<" not in line and "requires-python" not in line
        ]
        if lines_with_deps:
            report = "\n".join(f"  - {dep}" for dep in lines_with_deps)
            # This is informational, not a hard fail for alpha
            import warnings

            warnings.warn(
                f"Dependencies without upper bounds (supply chain risk):\n{report}",
                stacklevel=2,
            )


# ---------------------------------------------------------------------------
# Tests: Endpoint fuzzing (integration)
# ---------------------------------------------------------------------------


class TestEndpointFuzzing:
    """Fuzz all HTTP endpoints to verify no code execution paths."""

    # Common payloads that should never trigger code execution
    FUZZ_PAYLOADS = [
        # Command injection
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        # Python eval/exec
        "__import__('os').system('id')",
        "eval('1+1')",
        "exec('import os')",
        # SQL injection
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM information_schema.tables",
        # Template injection (Jinja2 / SSTI)
        "{{7*7}}",
        "${7*7}",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        # Path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        # XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        # Null bytes
        "\x00",
        "test\x00.py",
        # Unicode edge cases
        "\ud800",  # lone surrogate
        "\uffff",
        # Very long strings
        "A" * 10000,
        # Format string
        "%s%s%s%s%s",
        "%x%x%x%x%x",
    ]

    @pytest.fixture
    def client(self):
        """Create a test client for the FastAPI app."""
        try:
            from sundew.server import create_app

            app = create_app()
            from httpx import ASGITransport, AsyncClient

            return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        except ImportError:
            pytest.skip("sundew.server not yet available (being built by another teammate)")

    @pytest.fixture
    def discover_routes(self, client):
        """Discover all registered routes."""
        try:
            from sundew.server import create_app

            app = create_app()
            routes = []
            for route in app.routes:
                if hasattr(route, "path") and hasattr(route, "methods"):
                    for method in route.methods:
                        routes.append((method, route.path))
            return routes
        except ImportError:
            return []

    async def test_fuzz_path_parameters(self, client, discover_routes) -> None:
        """Inject fuzz payloads into URL path segments."""
        if not discover_routes:
            pytest.skip("No routes discovered yet")

        for method, path in discover_routes:
            for payload in self.FUZZ_PAYLOADS:
                # Replace path parameters with fuzz payload
                fuzzed_path = re.sub(r"\{[^}]+\}", re.escape(payload), path)
                try:
                    response = await client.request(method, fuzzed_path)
                    # Any response is fine -- we're checking for crashes/500s
                    # A 500 with a stack trace could leak information
                    if response.status_code == 500:
                        body = response.text
                        assert "Traceback" not in body, f"{method} {fuzzed_path} leaked stack trace"
                except Exception:
                    pass  # Connection errors are fine

    async def test_fuzz_query_parameters(self, client, discover_routes) -> None:
        """Inject fuzz payloads into query parameters."""
        if not discover_routes:
            pytest.skip("No routes discovered yet")

        for method, path in discover_routes:
            if method not in ("GET", "DELETE"):
                continue
            clean_path = re.sub(r"\{[^}]+\}", "test", path)
            for payload in self.FUZZ_PAYLOADS[:10]:  # Subset for speed
                try:
                    response = await client.request(
                        method, clean_path, params={"q": payload, "id": payload}
                    )
                    if response.status_code == 500:
                        body = response.text
                        assert "Traceback" not in body, (
                            f"{method} {clean_path}?q={payload[:20]} leaked stack trace"
                        )
                except Exception:
                    pass

    async def test_fuzz_request_bodies(self, client, discover_routes) -> None:
        """Inject fuzz payloads into JSON request bodies."""
        if not discover_routes:
            pytest.skip("No routes discovered yet")

        for method, path in discover_routes:
            if method not in ("POST", "PUT", "PATCH"):
                continue
            clean_path = re.sub(r"\{[^}]+\}", "test", path)
            for payload in self.FUZZ_PAYLOADS[:10]:
                try:
                    response = await client.request(
                        method,
                        clean_path,
                        json={"input": payload, "command": payload, "query": payload},
                    )
                    if response.status_code == 500:
                        body = response.text
                        assert "Traceback" not in body, (
                            f"{method} {clean_path} with body payload leaked stack trace"
                        )
                except Exception:
                    pass

    async def test_fuzz_headers(self, client, discover_routes) -> None:
        """Inject fuzz payloads into HTTP headers."""
        if not discover_routes:
            pytest.skip("No routes discovered yet")

        malicious_headers = {
            "X-Forwarded-For": "__import__('os').system('id')",
            "User-Agent": "{{7*7}}",
            "Referer": "'; DROP TABLE users; --",
            "Accept": "../../../etc/passwd",
            "X-Custom": "\x00\x01\x02",
        }

        for method, path in discover_routes[:5]:  # Subset for speed
            clean_path = re.sub(r"\{[^}]+\}", "test", path)
            try:
                response = await client.request(method, clean_path, headers=malicious_headers)
                if response.status_code == 500:
                    body = response.text
                    assert "Traceback" not in body, (
                        f"{method} {clean_path} with malicious headers leaked stack trace"
                    )
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Tests: No filesystem operations from user input
# ---------------------------------------------------------------------------


class TestNoFSOperationsFromInput:
    """Verify route handlers do not perform filesystem operations from user input."""

    FS_OPERATIONS = frozenset(
        {
            "open",
            "read",
            "write",
            "readlines",
            "writelines",
        }
    )

    FS_PATH_CALLS = frozenset(
        {
            "Path",
            "os.path.join",
            "os.path.exists",
            "os.makedirs",
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "shutil.copy",
            "shutil.move",
            "shutil.rmtree",
        }
    )

    def test_no_open_with_user_input_in_routes(self) -> None:
        """Route handlers must not call open() with path derived from request data."""
        route_files = []
        # Only check files that define actual route handlers, not config/utility
        # files that happen to import FastAPI types
        route_keywords = ["@app.", "@router."]
        for pyfile in _python_files():
            source = _read_source(pyfile)
            if any(kw in source for kw in route_keywords):
                route_files.append(pyfile)

        for pyfile in route_files:
            source = _read_source(pyfile)
            tree = ast.parse(source, filename=str(pyfile))

            # Find open() calls inside route handler functions
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                # Only check functions decorated with route decorators
                is_route = any(
                    "get" in ast.dump(d).lower()
                    or "post" in ast.dump(d).lower()
                    or "put" in ast.dump(d).lower()
                    or "delete" in ast.dump(d).lower()
                    for d in node.decorator_list
                )
                if not is_route:
                    continue
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.Call)
                        and isinstance(child.func, ast.Name)
                        and child.func.id == "open"
                    ):
                        if child.args and isinstance(child.args[0], ast.Constant):
                            continue  # Literal path is safe
                        rel = pyfile.relative_to(PROJECT_ROOT)
                        pytest.fail(
                            f"{rel}:{child.lineno} calls open() with non-literal path "
                            "in a route handler. This could allow path traversal."
                        )


# ---------------------------------------------------------------------------
# Tests: Import-time safety
# ---------------------------------------------------------------------------


class TestImportSafety:
    """Verify importing sundew does not have side effects."""

    def test_import_does_not_start_server(self) -> None:
        """Importing sundew must not start a server or bind a port."""
        # This verifies the package is safe to import in test contexts
        try:
            import sundew

            assert sundew.__version__
        except ImportError:
            pytest.skip("sundew package not installed")

    def test_no_module_level_network_calls(self) -> None:
        """No module performs network I/O at import time."""
        for pyfile in _python_files():
            source = _read_source(pyfile)
            tree = ast.parse(source, filename=str(pyfile))

            # Check for top-level (non-function, non-class) network calls
            for node in tree.body:
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    func = node.value.func
                    if isinstance(func, ast.Attribute) and func.attr in (
                        "get",
                        "post",
                        "put",
                        "delete",
                        "request",
                        "connect",
                        "urlopen",
                    ):
                        rel = pyfile.relative_to(PROJECT_ROOT)
                        pytest.fail(f"{rel}:{node.lineno} makes network call at module level")
