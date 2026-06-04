"""Rule implementations for security and repository hygiene checks."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .crawler import CrawledFile
from .models import ControlResult, Finding, Severity

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    (
        "Likely hard-coded secret",
        re.compile(
            r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{12,}['\"]"
        ),
    ),
)

_DANGEROUS_CODE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("PY001", "Python dynamic code execution", re.compile(r"\b(eval|exec)\s*\(")),
    ("PY002", "Python shell command execution", re.compile(r"subprocess\.(Popen|call|run)\([^\n]*shell\s*=\s*True")),
    ("JS001", "JavaScript dynamic code execution", re.compile(r"\b(eval|Function)\s*\(")),
    ("SQL001", "Possible string-built SQL query", re.compile(r"(?i)(select|insert|update|delete).*(\+|%|\.format\(|f['\"])")),
    ("PHP001", "PHP dynamic code execution", re.compile(r"\b(eval|assert)\s*\(\s*\$")),
    ("PHP002", "PHP shell command execution", re.compile(r"\b(system|shell_exec|passthru|exec|popen|proc_open)\s*\(")),
    ("RB001", "Ruby dynamic code execution", re.compile(r"\b(eval|instance_eval|class_eval|module_eval)\s*[\(\"]")),
    ("RB002", "Ruby shell command execution", re.compile(r"(`[^`]+`|\bsystem\s*\(|\bexec\s*\(|\bIO\.popen\s*\(|\bOpen3\.(popen|capture))")),
    ("JAVA001", "Java reflection or dynamic class loading", re.compile(r"\b(Class\.forName|getDeclaredMethod|getDeclaredField|newInstance)\s*\(")),
    ("CS001", "C# dynamic code or process execution", re.compile(r"\b(Process\.Start|Assembly\.Load|Activator\.CreateInstance|Type\.GetType)\s*\(")),
    ("GO001", "Go shell command execution", re.compile(r'exec\.Command\s*\(\s*"(sh|bash|cmd|powershell)"')),
    ("CPP001", "C/C++ unsafe string function", re.compile(r"\b(strcpy|strcat|gets|vsprintf|scanf)\s*\(")),
    ("CPP002", "C/C++ format string vulnerability", re.compile(r"\b(printf|fprintf|syslog)\s*\(\s*[A-Za-z_]\w*\s*\)")),
    ("SH001", "Shell dynamic evaluation", re.compile(r"""\beval\s+["'`]?\$""")),
)

_ENTERPRISE_SECURITY_PATTERNS: tuple[tuple[str, str, Severity, str, re.Pattern[str], str], ...] = (
    (
        "SEC007",
        "TLS certificate verification disabled",
        Severity.HIGH,
        "Disabled TLS verification allows man-in-the-middle attacks.",
        re.compile(r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|curl\s+[^\n]*-k\b|wget\s+[^\n]*--no-check-certificate)"),
        "Keep certificate verification enabled and install trusted CA roots where needed.",
    ),
    (
        "SEC008",
        "Unsafe deserialization API",
        Severity.HIGH,
        "Unsafe deserialization can enable remote code execution with attacker-controlled data.",
        re.compile(r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\(|marshal\.loads?\s*\(|ObjectInputStream\s*\(|BinaryFormatter\s*\()"),
        "Use safe parsers such as yaml.safe_load and never deserialize untrusted input.",
    ),
    (
        "SEC009",
        "Weak cryptographic primitive",
        Severity.MEDIUM,
        "Weak hashes, ciphers, or modes are unsuitable for protecting sensitive data.",
        re.compile(r"(?i)(hashlib\.(md5|sha1)\s*\(|createHash\(['\"](md5|sha1)['\"]\)|\b(MD5|SHA1|DES|RC4)\b|AES\/ECB|MODE_ECB)"),
        "Use modern primitives such as SHA-256+, authenticated encryption, bcrypt/argon2, and vetted libraries.",
    ),
    (
        "SEC010",
        "Permissive CORS policy",
        Severity.MEDIUM,
        "Wildcard CORS can expose APIs to untrusted browser origins.",
        re.compile(r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*|CORS\([^\n]*origins?\s*=\s*['\"]\*|cors\([^\n]*origin\s*:\s*['\"]\*)"),
        "Restrict CORS origins to known trusted domains and avoid credentials with wildcard origins.",
    ),
    (
        "SEC011",
        "Potential command injection sink",
        Severity.HIGH,
        "Process execution built from strings can allow command injection.",
        re.compile(r"(?i)(os\.system\s*\(|os\.popen\s*\(|child_process\.(exec|execSync)\s*\(|Runtime\.getRuntime\(\)\.exec\s*\()"),
        "Pass arguments as arrays, validate inputs, and avoid shell interpolation.",
    ),
    (
        "SEC012",
        "Container image or package uses latest tag",
        Severity.MEDIUM,
        "Floating versions make deployments non-reproducible and can silently pull vulnerable releases.",
        re.compile(r"(?i)^\s*(FROM\s+[^\s:]+\s*$|FROM\s+[^\s]+:latest\b|image\s*:\s*[^\s:]+:latest\b|version\s*[:=]\s*['\"]?latest['\"]?)"),
        "Pin base images and packages to reviewed versions or immutable digests.",
    ),
    (
        "SEC013",
        "Dockerfile lacks explicit non-root user",
        Severity.MEDIUM,
        "Containers that run as root increase blast radius after compromise.",
        re.compile(r"(?!)"),
        "Set USER to a dedicated non-root account and minimize Linux capabilities.",
    ),
    (
        "SEC014",
        "Risky install script execution",
        Severity.HIGH,
        "Piping downloaded scripts directly to an interpreter bypasses review and integrity checks.",
        re.compile(r"(?i)(curl\s+[^\n]*(\|\s*(sh|bash|python|ruby))|wget\s+[^\n]*(\|\s*(sh|bash|python|ruby)))"),
        "Download, verify checksums/signatures, review, then execute trusted installation artifacts.",
    ),
    (
        "SEC015",
        "Potential path traversal",
        Severity.HIGH,
        "Unsanitized user input used to build file paths can allow directory traversal attacks.",
        re.compile(r"(?i)(open\s*\(|file_get_contents\s*\(|readFile\s*\(|File\s*\().*\.\./|\.\./.*\$_(GET|POST|REQUEST|COOKIE)"),
        "Canonicalize file paths with realpath/os.path.abspath and validate they are within the expected root.",
    ),
    (
        "SEC016",
        "Unsafe XML parsing (XXE risk)",
        Severity.HIGH,
        "Default XML parsers in many frameworks resolve external entities, enabling XXE attacks.",
        re.compile(r"(?i)(DocumentBuilderFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)|etree\.parse\s*\(|xml\.etree|libxml_disable_entity_loader\s*\(\s*false)"),
        "Disable external entity resolution: set FEATURE_SECURE_PROCESSING or use defusedxml in Python.",
    ),
    (
        "SEC017",
        "Potential server-side request forgery (SSRF) sink",
        Severity.HIGH,
        "Fetching remote URLs derived from user input can allow SSRF attacks to internal services.",
        re.compile(r"(?i)(requests\.get\s*\(\s*\$|requests\.post\s*\(\s*\$|urllib\.request\.urlopen\s*\(\s*\$|fetch\s*\(\s*(req\.|request\.|params\.|query\.)|file_get_contents\s*\(\s*\$_(GET|POST|REQUEST))"),
        "Validate and allowlist URLs; never fetch arbitrary user-controlled URLs without strict filtering.",
    ),
    (
        "SEC018",
        "Hardcoded cryptographic key or IV",
        Severity.HIGH,
        "Hardcoded keys or initialization vectors make cryptographic protections trivially bypassable.",
        re.compile(r"(?i)(aes_key|secret_key|encryption_key|iv\s*=|AES\.new\s*\([^,]+,\s*AES\.[A-Z]+,\s*b['\"])\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        "Generate keys securely at runtime and store them in a key management service, never in source code.",
    ),
    (
        "SEC019",
        "JWT algorithm none or weak algorithm",
        Severity.HIGH,
        "Accepting 'none' as a JWT algorithm or using HS256 with untrusted keys bypasses signature verification.",
        re.compile(r"(?i)(algorithm\s*=\s*['\"]none['\"]|algorithms\s*=\s*\[['\"]none['\"]\]|verify\s*=\s*False.*jwt|jwt\.decode.*verify.*False)"),
        "Always specify a strong algorithm list (RS256/ES256) and never disable signature verification.",
    ),
    (
        "SEC020",
        "Potential open redirect",
        Severity.MEDIUM,
        "Redirecting to a URL derived from user input without validation can enable phishing.",
        re.compile(r"(?i)(redirect\s*\(\s*request\.(args|params|GET|POST)|HttpResponseRedirect\s*\(\s*request\.(GET|POST)|res\.redirect\s*\(\s*req\.(query|body|params))"),
        "Validate redirect targets against an allowlist of known-safe URLs or paths.",
    ),
    (
        "SEC021",
        "Server-side template injection sink",
        Severity.HIGH,
        "Rendering user-controlled strings as templates enables remote code execution.",
        re.compile(r"(?i)(render_template_string\s*\(|Template\s*\(\s*(request\.|params\.|query\.|\$_(GET|POST))|Mustache\.render\s*\([^,]+,\s*(req\.|request\.)|\{\{.*user|\.render\s*\(\s*(params|request))"),
        "Never pass user input directly to template engines; use static template files with context variables.",
    ),
    (
        "SEC022",
        "Debug mode enabled",
        Severity.MEDIUM,
        "Running web frameworks in debug mode can expose stack traces, secrets, and an interactive console in production.",
        re.compile(r"(?i)(DEBUG\s*=\s*True|app\.run\([^\n]*debug\s*=\s*True|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|APP_DEBUG\s*=\s*true|display_errors\s*=\s*On)"),
        "Disable debug mode in production and gate it behind an environment variable that defaults to off.",
    ),
    (
        "SEC023",
        "Insecure randomness in security context",
        Severity.MEDIUM,
        "Non-cryptographic randomness is predictable and unsafe for tokens, secrets, passwords, or nonces.",
        re.compile(r"(?i)(random\.(random|randint|randrange|choice|choices|sample)\s*\([^\n]*(token|secret|password|passwd|key|nonce|otp|salt|session)|(Math\.random|mt_rand|rand)\s*\([^\n]*(token|secret|password|key|nonce|otp|salt|session))"),
        "Use a cryptographically secure RNG such as secrets, os.urandom, crypto.randomBytes, or SecureRandom.",
    ),
    (
        "SEC024",
        "Insecure cookie configuration",
        Severity.MEDIUM,
        "Cookies without HttpOnly/Secure or with SameSite=None can be stolen via XSS or sent over insecure channels.",
        re.compile(r"(?i)(httponly\s*[:=]\s*false|secure\s*[:=]\s*false|samesite\s*[:=]\s*['\"]?none['\"]?|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False)"),
        "Set HttpOnly and Secure on session cookies and prefer SameSite=Lax or Strict.",
    ),
    (
        "SEC025",
        "Potential cross-site scripting (XSS) sink",
        Severity.HIGH,
        "Writing unsanitized user input into the DOM or HTML responses can enable cross-site scripting.",
        re.compile(r"(?i)(\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|insertAdjacentHTML\s*\(|\.html\s*\(\s*(req\.|request\.|params|query|data\b)|\|\s*safe\b|\|\s*raw\b|mark_safe\s*\()"),
        "Escape or sanitize untrusted output and prefer textContent or framework-provided escaping.",
    ),
    (
        "SEC026",
        "CSRF protection disabled",
        Severity.HIGH,
        "Disabling CSRF protection lets attackers forge authenticated state-changing requests.",
        re.compile(r"(?i)(csrf_exempt|@csrf\.exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*[:=]\s*false|csrfProtection\s*:\s*false|VerifyCsrfToken)"),
        "Keep CSRF protection enabled for all state-changing endpoints and use per-session tokens.",
    ),
    (
        "SEC027",
        "Potential LDAP injection sink",
        Severity.HIGH,
        "Building LDAP filters from unescaped user input can allow authentication bypass or data disclosure.",
        re.compile(r"(?i)(search_s?\s*\([^\n]*\+|InitialDirContext|\(uid=['\"]?\s*\+|\(cn=['\"]?\s*\+|ldap_search\s*\([^\n]*\$)"),
        "Escape LDAP special characters and use parameterized filter builders.",
    ),
    (
        "SEC028",
        "Service binds to all network interfaces",
        Severity.LOW,
        "Binding to 0.0.0.0 exposes the service on every interface, which may be unintended outside containers.",
        re.compile(r"(?i)(host\s*[:=]\s*['\"]0\.0\.0\.0['\"]|--host[= ]0\.0\.0\.0|\b0\.0\.0\.0:\d+|ListenAndServe\s*\(\s*['\"]:\d+|bind\s*\(\s*\(\s*['\"]0\.0\.0\.0['\"])"),
        "Bind to a specific interface or localhost unless external exposure is intended and firewalled.",
    ),
    (
        "SEC029",
        "Potential NoSQL injection sink",
        Severity.HIGH,
        "Building NoSQL queries from user input can allow query operator injection and authentication bypass.",
        re.compile(r"(?i)(\$where\s*[:=]|db\.[A-Za-z_]+\.find\s*\([^\n]*(req\.(query|body|params)|request\.)|\{\s*\$ne\s*:|\$regex\s*:[^\n]*(req\.|request\.))"),
        "Validate and cast input types, and never pass raw user objects into query filters.",
    ),
    (
        "SEC030",
        "Potential XPath injection sink",
        Severity.HIGH,
        "Building XPath expressions from unescaped user input can disclose data or bypass authentication.",
        re.compile(r"(?i)((evaluate|selectNodes|selectSingleNode|compile)\s*\([^\n]*\+[^\n]*(request|params|input|user)|xpath[^\n]*\+\s*(req|request|params|user))"),
        "Use parameterized XPath APIs and escape special characters in user input.",
    ),
    (
        "SEC031",
        "Potential CRLF / HTTP response splitting",
        Severity.MEDIUM,
        "Injecting CR/LF sequences into headers or redirects can split responses and poison caches.",
        re.compile(r"(?i)((setHeader|addHeader|set_header|header)\s*\([^\n]*(\\r|\\n|%0d|%0a)|Location\s*:[^\n]*\+[^\n]*(req\.|request\.|params|input))"),
        "Strip CR/LF from header values and use framework header APIs that reject them.",
    ),
    (
        "SEC032",
        "Potential log injection",
        Severity.LOW,
        "Writing unsanitized user input into logs can forge log entries or break log processing.",
        re.compile(r"(?i)(log(ger)?\.(info|debug|warn|warning|error)\s*\([^\n]*\+\s*(req\.|request\.|params|user)|console\.log\s*\([^\n]*\b(req|request)\.(query|body|params))"),
        "Sanitize or encode untrusted values and prefer structured logging with separate fields.",
    ),
    (
        "SEC033",
        "Potential regular expression denial of service (ReDoS)",
        Severity.MEDIUM,
        "Nested quantifiers can cause catastrophic backtracking and denial of service on crafted input.",
        re.compile(r"\([^()]*[+*]\)\s*[+*]"),
        "Rewrite the pattern to avoid nested quantifiers or use a linear-time regex engine.",
    ),
    (
        "SEC034",
        "Potential prototype pollution",
        Severity.HIGH,
        "Assigning to __proto__ or prototype from user input can pollute object prototypes across the app.",
        re.compile(r"(?i)(\[['\"]__proto__['\"]\]|\.__proto__\b|Object\.prototype\s*\[|constructor\s*\[\s*['\"]prototype['\"]\])"),
        "Validate object keys, freeze prototypes, and use Map or null-prototype objects for untrusted data.",
    ),
    (
        "SEC035",
        "Weak password hashing",
        Severity.HIGH,
        "Fast or unsalted hashes like MD5/SHA1 are unsuitable for password storage and are easily cracked.",
        re.compile(r"(?i)((md5|sha1)\s*\([^)\n]*(password|passwd|pwd|secret)|(password|passwd|pwd)[^\n]*\b(md5|sha1)\s*\()"),
        "Use a dedicated password hash such as bcrypt, scrypt, or Argon2 with a per-user salt.",
    ),
    (
        "SEC036",
        "Weak asymmetric key size",
        Severity.MEDIUM,
        "RSA/DSA keys below 2048 bits are considered weak and should not be used for new keys.",
        re.compile(r"(?i)(key_size\s*=\s*(512|1024)\b|RSA\.generate\s*\(\s*(512|1024)\b|KeyPairGenerator[^\n]*\.initialize\s*\(\s*(512|1024)\b|rsa\.GenerateKey\([^\n]*\b(512|1024)\b)"),
        "Use at least 2048-bit RSA/DSA keys, or prefer modern elliptic-curve keys.",
    ),
    (
        "SEC037",
        "Obsolete TLS/SSL protocol",
        Severity.HIGH,
        "SSLv2/SSLv3 and TLS 1.0/1.1 are deprecated and vulnerable to known attacks.",
        re.compile(r"(?i)(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|PROTOCOL_SSLv\d|PROTOCOL_TLSv1(?![._]?[23]))"),
        "Require TLS 1.2 or higher and disable legacy protocol versions.",
    ),
    (
        "SEC038",
        "Default or hardcoded credentials",
        Severity.HIGH,
        "Default or trivial credentials in source are well-known and routinely targeted.",
        re.compile(r"(?i)(password\s*[:=]\s*['\"](admin|root|password|passw0rd|123456|changeme|admin123|secret)['\"]|user(name)?\s*[:=]\s*['\"]admin['\"][^\n]*password)"),
        "Remove default credentials, require setup-time secrets, and load them from a secret manager.",
    ),
    (
        "SEC039",
        "Security headers disabled",
        Severity.MEDIUM,
        "Explicitly disabling CSP, HSTS, or frame protection removes important browser-side defenses.",
        re.compile(r"(?i)(contentSecurityPolicy\s*:\s*false|hsts\s*:\s*false|frameguard\s*:\s*false|X-Frame-Options['\"]?\s*[:=]\s*['\"]?ALLOWALL|helmet\s*:\s*false)"),
        "Enable CSP, HSTS, X-Frame-Options, and X-Content-Type-Options on HTTP responses.",
    ),
    (
        "SEC040",
        "Directory listing enabled",
        Severity.LOW,
        "Automatic directory listings can expose files that were not meant to be browsable.",
        re.compile(r"(?i)(autoindex\s+on\b|Options\s+[^\n]*\bIndexes\b|serveIndex\s*\()"),
        "Disable directory indexing and serve only explicitly intended files.",
    ),
    (
        "SEC041",
        "Verbose error or stack trace exposure",
        Severity.LOW,
        "Returning stack traces or full exception detail to clients leaks internal implementation information.",
        re.compile(r"(?i)(\.printStackTrace\s*\(|traceback\.print_exc\s*\(|PROPAGATE_EXCEPTIONS['\"]?\s*\]?\s*=\s*True)"),
        "Log details server-side and return generic error messages to clients.",
    ),
    (
        "SEC042",
        "Dockerfile ADD from remote URL",
        Severity.MEDIUM,
        "ADD with a remote URL fetches content without integrity verification and can hide supply-chain risk.",
        re.compile(r"(?i)^\s*ADD\s+https?://"),
        "Use COPY for local files, or download with verified checksums in a RUN step.",
    ),
    (
        "SEC043",
        "Privileged container",
        Severity.HIGH,
        "Privileged containers can access host devices and effectively escape isolation.",
        re.compile(r"(?i)(privileged\s*:\s*true|--privileged\b)"),
        "Avoid privileged mode; grant only the specific Linux capabilities required.",
    ),
    (
        "SEC044",
        "Host namespace sharing",
        Severity.HIGH,
        "Sharing host network, PID, or IPC namespaces breaks container isolation.",
        re.compile(r"(?i)(hostNetwork\s*:\s*true|hostPID\s*:\s*true|hostIPC\s*:\s*true)"),
        "Disable host namespace sharing unless strictly required and tightly controlled.",
    ),
    (
        "SEC045",
        "Container privilege escalation or root user",
        Severity.MEDIUM,
        "Allowing privilege escalation or running as UID 0 increases blast radius after compromise.",
        re.compile(r"(?i)(allowPrivilegeEscalation\s*:\s*true|runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0\b)"),
        "Set runAsNonRoot, a non-zero UID, and allowPrivilegeEscalation: false.",
    ),
    (
        "SEC046",
        "Secret in container build variable",
        Severity.HIGH,
        "Secrets in ENV/ARG are baked into image layers and can be extracted from the image history.",
        re.compile(r"(?i)^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)\w*\s*[=\s]"),
        "Use build secrets or runtime secret injection instead of ENV/ARG for credentials.",
    ),
    (
        "SEC047",
        "Open network ACL or public cloud resource",
        Severity.HIGH,
        "Allowing 0.0.0.0/0 ingress or public ACLs exposes resources to the entire internet.",
        re.compile(r"(?i)(cidr_blocks?\s*=\s*\[?\s*['\"]0\.0\.0\.0/0['\"]|0\.0\.0\.0/0|acl\s*=\s*['\"]public-read|publicly_accessible\s*=\s*true)"),
        "Restrict ingress to known CIDRs and keep storage resources private by default.",
    ),
    (
        "SEC048",
        "Unencrypted storage resource",
        Severity.MEDIUM,
        "Disabling encryption-at-rest leaves stored data unprotected if the medium is compromised.",
        re.compile(r"(?i)((storage_)?encrypted\s*=\s*false|encryption\s*=\s*false)"),
        "Enable encryption-at-rest for volumes, buckets, and databases.",
    ),
    (
        "SEC049",
        "GitHub Actions pull_request_target trigger",
        Severity.MEDIUM,
        "pull_request_target runs with repository secrets and can be abused if it checks out untrusted code.",
        re.compile(r"(?i)pull_request_target\b"),
        "Avoid checking out and executing PR code under pull_request_target, or use a hardened pattern.",
    ),
    (
        "SEC050",
        "Unpinned CI action reference",
        Severity.MEDIUM,
        "Referencing actions by mutable refs like @master/@main allows silent and potentially malicious updates.",
        re.compile(r"(?i)uses\s*:\s*[A-Za-z0-9_./-]+@(master|main|latest)\b"),
        "Pin third-party actions to a full commit SHA or an immutable release tag.",
    ),
    (
        "SEC051",
        "GitHub Actions expression injection",
        Severity.MEDIUM,
        "Interpolating untrusted github.event fields into shell can allow command injection in workflows.",
        re.compile(r"\$\{\{\s*github\.event\.[^}]*\}\}"),
        "Pass untrusted values through env vars and quote them; avoid direct interpolation in run steps.",
    ),
    (
        "SEC052",
        "Missing Subresource Integrity",
        Severity.MEDIUM,
        "Loading external scripts without an integrity hash trusts the CDN to never serve tampered content.",
        re.compile(r"(?i)<script(?![^>]*\bintegrity\s*=)[^>]*\bsrc\s*=\s*['\"]https?://"),
        "Add an integrity attribute (and crossorigin) to externally hosted script and style tags.",
    ),
    (
        "SEC053",
        "Unsafe package install script",
        Severity.HIGH,
        "Install hooks that download and run remote code execute untrusted scripts during dependency setup.",
        re.compile(r"(?i)\"(pre|post)install\"\s*:\s*\"[^\"]*(curl|wget|https?://|node\s+-e)"),
        "Avoid network-fetching install hooks; vendor and verify any required setup scripts.",
    ),
)

_DEPENDENCY_MANIFESTS = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
}

_PACKAGE_MANIFESTS = {
    "package.json": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"},
    "pyproject.toml": {"poetry.lock", "Pipfile.lock", "uv.lock"},
    "Pipfile": {"Pipfile.lock"},
    "Cargo.toml": {"Cargo.lock"},
    "go.mod": {"go.sum"},
    "Gemfile": {"Gemfile.lock"},
    "composer.json": {"composer.lock"},
}

_SECURITY_DOC_NAMES = {"security.md", "security.txt"}
_README_NAMES = {"readme", "readme.md", "readme.rst", "readme.txt"}
_LICENSE_NAMES = {"license", "license.md", "license.txt", "copying"}
_TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__"}
_CI_HINTS = {".github/workflows", ".gitlab-ci.yml", "circle.yml", ".circleci", "azure-pipelines.yml"}
_SAFE_HTTP_HOSTS = {"localhost", "127.0.0.1", "schemas.openxmlformats.org"}
_PINNED_OPERATORS = ("==", "===")
_FLOATING_VERSION_PREFIXES = ("^", "~", ">", "<", "*", "x", "X")

# Conservative curated floor versions for dependencies with widely exploited or high-impact
# historical vulnerabilities. This does not replace a live SCA feed; it catches risky legacy pins.
_VULNERABLE_DEPENDENCY_FLOORS: dict[str, tuple[str, str]] = {
    "django": ("4.2.11", "Python"),
    "flask": ("2.3.3", "Python"),
    "requests": ("2.32.0", "Python"),
    "urllib3": ("2.0.7", "Python"),
    "pyyaml": ("6.0.1", "Python"),
    "cryptography": ("42.0.4", "Python"),
    "pillow": ("10.3.0", "Python"),
    "jinja2": ("3.1.4", "Python"),
    "werkzeug": ("3.0.3", "Python"),
    "lodash": ("4.17.21", "npm"),
    "minimist": ("1.2.8", "npm"),
    "axios": ("1.6.8", "npm"),
    "express": ("4.18.2", "npm"),
    "semver": ("7.5.2", "npm"),
    "node-fetch": ("3.2.10", "npm"),
    "log4j-core": ("2.17.1", "Maven"),
    # Python extras
    "fastapi": ("0.109.1", "Python"),
    "sqlalchemy": ("2.0.25", "Python"),
    "aiohttp": ("3.9.4", "Python"),
    "paramiko": ("3.4.0", "Python"),
    "starlette": ("0.36.2", "Python"),
    # npm extras
    "jsonwebtoken": ("9.0.0", "npm"),
    "passport": ("0.6.0", "npm"),
    "multer": ("1.4.5-lts.1", "npm"),
    "ws": ("8.17.1", "npm"),
    "tar": ("6.2.1", "npm"),
    # Ruby (Gem)
    "rails": ("7.0.8.4", "Ruby"),
    "rack": ("3.0.10", "Ruby"),
    "devise": ("4.9.4", "Ruby"),
    "carrierwave": ("3.0.7", "Ruby"),
    "nokogiri": ("1.16.5", "Ruby"),
    "activerecord": ("7.0.8.4", "Ruby"),
    # PHP (Composer)
    "laravel/framework": ("10.48.16", "PHP"),
    "symfony/http-foundation": ("6.4.6", "PHP"),
    "symfony/http-kernel": ("6.4.6", "PHP"),
    "guzzlehttp/guzzle": ("7.8.1", "PHP"),
    "monolog/monolog": ("3.5.0", "PHP"),
    # Java/Maven extras
    "spring-core": ("6.1.6", "Maven"),
    "spring-web": ("6.1.6", "Maven"),
    "spring-webmvc": ("6.1.6", "Maven"),
    "spring-boot": ("3.2.5", "Maven"),
    "spring-boot-autoconfigure": ("3.2.5", "Maven"),
    "spring-security-core": ("6.2.4", "Maven"),
    "commons-collections": ("3.2.2", "Maven"),
    "commons-collections4": ("4.4", "Maven"),
    "commons-text": ("1.10.0", "Maven"),
    "commons-compress": ("1.26.0", "Maven"),
    "commons-io": ("2.14.0", "Maven"),
    "commons-fileupload": ("1.5", "Maven"),
    "jackson-databind": ("2.17.0", "Maven"),
    "snakeyaml": ("2.0", "Maven"),
    "fastjson": ("1.2.83", "Maven"),
    "struts2-core": ("2.5.33", "Maven"),
    "bcprov-jdk15on": ("1.70", "Maven"),
    "bcprov-jdk18on": ("1.78", "Maven"),
    "tomcat-embed-core": ("10.1.20", "Maven"),
    "guava": ("32.0.0", "Maven"),
    "httpclient": ("4.5.13", "Maven"),
    "netty-all": ("4.1.108.Final", "Maven"),
    "netty-handler": ("4.1.108.Final", "Maven"),
    "hibernate-core": ("6.4.4", "Maven"),
    "h2": ("2.2.220", "Maven"),
    "junit": ("4.13.2", "Maven"),
    # Go modules
    "golang.org/x/net": ("0.23.0", "Go"),
    "golang.org/x/crypto": ("0.22.0", "Go"),
    "github.com/gin-gonic/gin": ("1.9.1", "Go"),
    "github.com/dgrijalva/jwt-go": ("3.2.1", "Go"),
    "github.com/gorilla/websocket": ("1.5.1", "Go"),
}

RULE_CATALOG: tuple[ControlResult, ...] = (
    ControlResult("SEC001", "Potential secret committed", Severity.CRITICAL, "security", "passed", recommendation="Rotate committed credentials and load secrets from a secret manager or environment variables."),
    ControlResult("SEC002", "Security policy present", Severity.MEDIUM, "security", "passed", recommendation="Add SECURITY.md with vulnerability reporting and supported versions."),
    ControlResult("SEC003", "Dependency scanner configured", Severity.MEDIUM, "security", "passed", recommendation="Enable Dependabot, Renovate, pip-audit, npm audit, or an equivalent dependency scanner."),
    ControlResult("SEC004", "External URLs use HTTPS", Severity.MEDIUM, "security", "passed", recommendation="Use HTTPS for external endpoints whenever possible."),
    ControlResult("SEC005", "Dependencies are pinned", Severity.MEDIUM, "security", "passed", recommendation="Pin direct dependencies to exact reviewed versions and use lock files for applications."),
    ControlResult("SEC006", "Known vulnerable dependency floor", Severity.HIGH, "security", "passed", recommendation="Upgrade flagged legacy dependencies and run a current SCA scanner before release."),
    ControlResult("SEC007", "TLS verification enabled", Severity.HIGH, "security", "passed", recommendation="Keep TLS certificate verification enabled and trust explicit CA bundles when needed."),
    ControlResult("SEC008", "Safe deserialization", Severity.HIGH, "security", "passed", recommendation="Use safe parsers and never deserialize untrusted data."),
    ControlResult("SEC009", "Strong cryptography", Severity.MEDIUM, "security", "passed", recommendation="Replace weak hashes/ciphers with modern vetted primitives."),
    ControlResult("SEC010", "CORS restricted", Severity.MEDIUM, "security", "passed", recommendation="Restrict browser origins to trusted domains."),
    ControlResult("SEC011", "Command injection sinks avoided", Severity.HIGH, "security", "passed", recommendation="Avoid shell strings and pass validated arguments as arrays."),
    ControlResult("SEC012", "No latest/floating runtime tags", Severity.MEDIUM, "security", "passed", recommendation="Pin runtime images and package versions to reviewed releases or digests."),
    ControlResult("SEC013", "Container runs as non-root", Severity.MEDIUM, "security", "passed", recommendation="Set a non-root USER in Dockerfiles."),
    ControlResult("SEC014", "Installer scripts verified", Severity.HIGH, "security", "passed", recommendation="Verify downloaded install scripts before execution."),
    ControlResult("PY001", "Python dynamic code execution", Severity.HIGH, "security", "passed", recommendation="Avoid eval/exec or strictly validate inputs before dynamic execution."),
    ControlResult("PY002", "Python shell command execution", Severity.HIGH, "security", "passed", recommendation="Avoid shell=True and pass command arguments as a sequence."),
    ControlResult("JS001", "JavaScript dynamic code execution", Severity.HIGH, "security", "passed", recommendation="Avoid eval/Function constructors or strictly validate inputs."),
    ControlResult("SQL001", "Possible string-built SQL query", Severity.HIGH, "security", "passed", recommendation="Use parameterized queries or ORM-safe APIs."),
    ControlResult("PHP001", "PHP dynamic code execution", Severity.HIGH, "security", "passed", recommendation="Avoid eval/assert with user input; use static logic instead."),
    ControlResult("PHP002", "PHP shell command execution", Severity.HIGH, "security", "passed", recommendation="Avoid shell execution functions and use safer library APIs with validated inputs."),
    ControlResult("RB001", "Ruby dynamic code execution", Severity.HIGH, "security", "passed", recommendation="Avoid eval variants or strictly validate inputs before dynamic execution."),
    ControlResult("RB002", "Ruby shell command execution", Severity.HIGH, "security", "passed", recommendation="Avoid backticks and system/exec; use libraries with structured argument lists."),
    ControlResult("JAVA001", "Java reflection or dynamic class loading", Severity.HIGH, "security", "passed", recommendation="Avoid dynamic class loading with user-controlled input; use explicit allowlists."),
    ControlResult("CS001", "C# dynamic code or process execution", Severity.HIGH, "security", "passed", recommendation="Avoid Process.Start with shell and Assembly.Load with untrusted input."),
    ControlResult("GO001", "Go shell command execution", Severity.HIGH, "security", "passed", recommendation="Pass command arguments as separate strings instead of invoking sh/bash."),
    ControlResult("CPP001", "C/C++ unsafe string function", Severity.HIGH, "security", "passed", recommendation="Use bounded functions (strncpy/snprintf/fgets) and validate buffer sizes."),
    ControlResult("CPP002", "C/C++ format string vulnerability", Severity.MEDIUM, "security", "passed", recommendation="Always pass a constant format string and never user input as the format argument."),
    ControlResult("SH001", "Shell dynamic evaluation", Severity.HIGH, "security", "passed", recommendation="Avoid eval on variables; use arrays and quoting for safe command construction."),
    ControlResult("SEC015", "Path traversal prevented", Severity.HIGH, "security", "passed", recommendation="Canonicalize and validate file paths before use."),
    ControlResult("SEC016", "Safe XML parsing", Severity.HIGH, "security", "passed", recommendation="Disable external entity resolution in XML parsers."),
    ControlResult("SEC017", "SSRF sinks avoided", Severity.HIGH, "security", "passed", recommendation="Allowlist URLs before fetching user-controlled remote resources."),
    ControlResult("SEC018", "No hardcoded cryptographic keys", Severity.HIGH, "security", "passed", recommendation="Generate keys at runtime and store them in a KMS."),
    ControlResult("SEC019", "JWT algorithm validated", Severity.HIGH, "security", "passed", recommendation="Always specify a strong algorithm and never disable JWT verification."),
    ControlResult("SEC020", "Open redirect prevented", Severity.MEDIUM, "security", "passed", recommendation="Validate redirect targets against an allowlist."),
    ControlResult("SEC021", "Server-side template injection avoided", Severity.HIGH, "security", "passed", recommendation="Never render user input as a template string."),
    ControlResult("SEC022", "Debug mode disabled", Severity.MEDIUM, "security", "passed", recommendation="Disable debug mode in production and gate it behind an environment variable."),
    ControlResult("SEC023", "Secure randomness used", Severity.MEDIUM, "security", "passed", recommendation="Use a cryptographically secure RNG for tokens, secrets, and nonces."),
    ControlResult("SEC024", "Secure cookie configuration", Severity.MEDIUM, "security", "passed", recommendation="Set HttpOnly and Secure on session cookies and prefer SameSite=Lax or Strict."),
    ControlResult("SEC025", "Cross-site scripting sinks avoided", Severity.HIGH, "security", "passed", recommendation="Escape or sanitize untrusted output and avoid raw HTML sinks."),
    ControlResult("SEC026", "CSRF protection enabled", Severity.HIGH, "security", "passed", recommendation="Keep CSRF protection enabled for all state-changing endpoints."),
    ControlResult("SEC027", "LDAP injection sinks avoided", Severity.HIGH, "security", "passed", recommendation="Escape LDAP special characters and use parameterized filter builders."),
    ControlResult("SEC028", "Service binds to a specific interface", Severity.LOW, "security", "passed", recommendation="Bind to localhost or a specific interface unless external exposure is intended."),
    ControlResult("SEC029", "NoSQL injection sinks avoided", Severity.HIGH, "security", "passed", recommendation="Validate input types and never pass raw user objects into query filters."),
    ControlResult("SEC030", "XPath injection sinks avoided", Severity.HIGH, "security", "passed", recommendation="Use parameterized XPath APIs and escape user input."),
    ControlResult("SEC031", "CRLF / response splitting avoided", Severity.MEDIUM, "security", "passed", recommendation="Strip CR/LF from header values and use safe header APIs."),
    ControlResult("SEC032", "Log injection avoided", Severity.LOW, "security", "passed", recommendation="Sanitize untrusted values and prefer structured logging."),
    ControlResult("SEC033", "No catastrophic regex backtracking", Severity.MEDIUM, "security", "passed", recommendation="Avoid nested quantifiers or use a linear-time regex engine."),
    ControlResult("SEC034", "Prototype pollution avoided", Severity.HIGH, "security", "passed", recommendation="Validate object keys and use Map or null-prototype objects for untrusted data."),
    ControlResult("SEC035", "Strong password hashing", Severity.HIGH, "security", "passed", recommendation="Use bcrypt, scrypt, or Argon2 with a per-user salt."),
    ControlResult("SEC036", "Strong asymmetric key size", Severity.MEDIUM, "security", "passed", recommendation="Use at least 2048-bit RSA/DSA keys or modern elliptic-curve keys."),
    ControlResult("SEC037", "Modern TLS protocol", Severity.HIGH, "security", "passed", recommendation="Require TLS 1.2+ and disable legacy protocol versions."),
    ControlResult("SEC038", "No default/hardcoded credentials", Severity.HIGH, "security", "passed", recommendation="Remove default credentials and load secrets from a secret manager."),
    ControlResult("SEC039", "Security headers enabled", Severity.MEDIUM, "security", "passed", recommendation="Enable CSP, HSTS, X-Frame-Options, and X-Content-Type-Options."),
    ControlResult("SEC040", "Directory listing disabled", Severity.LOW, "security", "passed", recommendation="Disable directory indexing and serve only intended files."),
    ControlResult("SEC041", "No verbose error exposure", Severity.LOW, "security", "passed", recommendation="Log details server-side and return generic error messages to clients."),
    ControlResult("SEC042", "No remote ADD in Dockerfile", Severity.MEDIUM, "security", "passed", recommendation="Use COPY or download with verified checksums in a RUN step."),
    ControlResult("SEC043", "No privileged containers", Severity.HIGH, "security", "passed", recommendation="Avoid privileged mode; grant only required Linux capabilities."),
    ControlResult("SEC044", "No host namespace sharing", Severity.HIGH, "security", "passed", recommendation="Disable host network/PID/IPC namespace sharing unless required."),
    ControlResult("SEC045", "Container runs without escalation", Severity.MEDIUM, "security", "passed", recommendation="Set runAsNonRoot, a non-zero UID, and allowPrivilegeEscalation: false."),
    ControlResult("SEC046", "No secrets in build variables", Severity.HIGH, "security", "passed", recommendation="Use build secrets or runtime injection instead of ENV/ARG for credentials."),
    ControlResult("SEC047", "No open network ACLs", Severity.HIGH, "security", "passed", recommendation="Restrict ingress to known CIDRs and keep storage resources private."),
    ControlResult("SEC048", "Storage encryption enabled", Severity.MEDIUM, "security", "passed", recommendation="Enable encryption-at-rest for volumes, buckets, and databases."),
    ControlResult("SEC049", "No risky pull_request_target use", Severity.MEDIUM, "security", "passed", recommendation="Avoid checking out and executing untrusted PR code under pull_request_target."),
    ControlResult("SEC050", "CI actions pinned", Severity.MEDIUM, "security", "passed", recommendation="Pin third-party actions to a full commit SHA or immutable tag."),
    ControlResult("SEC051", "No Actions expression injection", Severity.MEDIUM, "security", "passed", recommendation="Pass untrusted values through quoted env vars rather than direct interpolation."),
    ControlResult("SEC052", "Subresource Integrity present", Severity.MEDIUM, "security", "passed", recommendation="Add integrity and crossorigin attributes to external script/style tags."),
    ControlResult("SEC053", "Safe package install scripts", Severity.HIGH, "security", "passed", recommendation="Avoid network-fetching install hooks; vendor and verify setup scripts."),
    ControlResult("HYG001", "README present", Severity.MEDIUM, "hygiene", "passed", recommendation="Add a README with setup, usage, testing, and security notes."),
    ControlResult("HYG002", "License present", Severity.LOW, "hygiene", "passed", recommendation="Add a license file so reuse terms are explicit."),
    ControlResult("HYG003", ".gitignore present", Severity.LOW, "hygiene", "passed", recommendation="Add a .gitignore tailored to the project stack."),
    ControlResult("HYG004", "Tests detected", Severity.MEDIUM, "hygiene", "passed", recommendation="Add automated tests and include the test command in documentation."),
    ControlResult("HYG005", "No unresolved maintenance markers", Severity.INFO, "hygiene", "passed", recommendation="Track maintenance debt in issues or resolve markers before release."),
    ControlResult("HYG006", "No large source files skipped", Severity.LOW, "hygiene", "passed", recommendation="Keep large generated artifacts out of source control or raise the scan limit deliberately."),
    ControlResult("HYG007", "CI configuration detected", Severity.LOW, "hygiene", "passed", recommendation="Add CI to run tests, linting, and security checks on every change."),
    ControlResult("HYG008", "Dependency lock files present", Severity.MEDIUM, "hygiene", "passed", recommendation="Commit lock files for applications so builds are reproducible."),
    ControlResult("HYG009", "Repository history clone mode reviewed", Severity.INFO, "hygiene", "info", recommendation="Use --depth 1 for large repositories when history is not needed."),
)


@dataclass(frozen=True)
class DependencySpec:
    name: str
    version_spec: str
    path: str
    line: int | None


class RuleEngine:
    """Runs security and hygiene rules over crawled files."""

    def run(self, root: Path, files: Iterable[CrawledFile]) -> list[Finding]:
        file_list = list(files)
        findings: list[Finding] = []
        findings.extend(self._scan_file_content(file_list))
        findings.extend(self._scan_dependencies(file_list))
        findings.extend(self._scan_repo_shape(root, file_list))
        return findings

    def _scan_file_content(self, files: list[CrawledFile]) -> list[Finding]:
        findings: list[Finding] = []
        for crawled in files:
            path = crawled.relative_path.as_posix()
            if crawled.skipped_reason:
                if crawled.skipped_reason == "file-too-large":
                    findings.append(
                        Finding(
                            rule_id="HYG006",
                            title="Large file skipped",
                            severity=Severity.LOW,
                            category="hygiene",
                            path=path,
                            message=f"File is {crawled.size} bytes and was not scanned.",
                            recommendation="Keep large generated artifacts out of source control or raise the scan limit deliberately.",
                        )
                    )
                continue
            if crawled.text is None:
                continue

            lines = crawled.text.splitlines()
            findings.extend(self._find_secrets(path, lines))
            findings.extend(self._find_dangerous_code(path, lines))
            findings.extend(self._find_todos(path, lines))
            findings.extend(self._find_insecure_urls(path, lines))
            findings.extend(self._find_enterprise_security_patterns(path, lines))
            findings.extend(self._find_dockerfile_hardening_issues(path, lines))
        return findings

    def _find_secrets(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for secret_name, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id="SEC001",
                            title=f"Potential secret committed: {secret_name}",
                            severity=Severity.CRITICAL,
                            category="security",
                            path=path,
                            line=line_number,
                            message="A value matching a secret pattern was found in source control.",
                            recommendation="Rotate the credential, remove it from history, and load secrets from a secret manager or environment variables.",
                        )
                    )
        return findings

    def _find_dangerous_code(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule_id, title, pattern in _DANGEROUS_CODE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            severity=Severity.HIGH,
                            category="security",
                            path=path,
                            line=line_number,
                            message="Dangerous construct detected by a lightweight static rule.",
                            recommendation="Validate inputs, avoid dynamic execution, and prefer safe library APIs.",
                        )
                    )
        return findings

    def _find_todos(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            if re.search(r"(?i)\b(TODO|FIXME|HACK)\b", line):
                findings.append(
                    Finding(
                        rule_id="HYG005",
                        title="Unresolved maintenance marker",
                        severity=Severity.INFO,
                        category="hygiene",
                        path=path,
                        line=line_number,
                        message="A TODO/FIXME/HACK marker was found.",
                        recommendation="Track maintenance debt in issues or resolve the marker before release.",
                    )
                )
        return findings

    def _find_insecure_urls(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for url in re.findall(r"http://[^\s'\"<>()]+", line):
                host = re.sub(r"^http://", "", url).split("/", 1)[0].lower()
                if host not in _SAFE_HTTP_HOSTS:
                    findings.append(
                        Finding(
                            rule_id="SEC004",
                            title="Plain HTTP URL",
                            severity=Severity.MEDIUM,
                            category="security",
                            path=path,
                            line=line_number,
                            message="Plain HTTP can expose traffic to interception or tampering.",
                            recommendation="Use HTTPS for external endpoints whenever possible.",
                        )
                    )
        return findings

    def _find_enterprise_security_patterns(self, path: str, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, start=1):
            for rule_id, title, severity, message, pattern, recommendation in _ENTERPRISE_SECURITY_PATTERNS:
                if rule_id == "SEC013":
                    continue
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            severity=severity,
                            category="security",
                            path=path,
                            line=line_number,
                            message=message,
                            recommendation=recommendation,
                        )
                    )
        return findings

    def _find_dockerfile_hardening_issues(self, path: str, lines: list[str]) -> list[Finding]:
        if Path(path).name.lower() not in {"dockerfile", "containerfile"} and not path.lower().endswith((".dockerfile", ".containerfile")):
            return []
        has_non_root_user = False
        user_line: int | None = None
        for line_number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.upper().startswith("USER "):
                user_line = line_number
                user = stripped.split(None, 1)[1].strip().strip('"\'')
                has_non_root_user = user not in {"0", "root"}
        if has_non_root_user:
            return []
        return [
            Finding(
                rule_id="SEC013",
                title="Dockerfile lacks explicit non-root user",
                severity=Severity.MEDIUM,
                category="security",
                path=path,
                line=user_line,
                message="No explicit non-root USER directive was detected in this container build file.",
                recommendation="Set USER to a dedicated non-root account and minimize Linux capabilities.",
            )
        ]

    def _scan_dependencies(self, files: list[CrawledFile]) -> list[Finding]:
        findings: list[Finding] = []
        for dependency in _iter_dependencies(files):
            normalized_name = _normalize_dependency_name(dependency.name)
            if _is_unpinned_dependency(dependency.version_spec):
                findings.append(
                    Finding(
                        rule_id="SEC005",
                        title=f"Unpinned dependency: {dependency.name}",
                        severity=Severity.MEDIUM,
                        category="security",
                        path=dependency.path,
                        line=dependency.line,
                        message=f"Dependency '{dependency.name}' uses non-exact version specifier '{dependency.version_spec}'.",
                        recommendation="Pin direct dependencies to exact reviewed versions and use lock files for applications.",
                    )
                )
            floor = _VULNERABLE_DEPENDENCY_FLOORS.get(normalized_name)
            exact_version = _extract_exact_version(dependency.version_spec)
            if floor and exact_version and _compare_versions(exact_version, floor[0]) < 0:
                findings.append(
                    Finding(
                        rule_id="SEC006",
                        title=f"Legacy vulnerable dependency floor: {dependency.name}",
                        severity=Severity.HIGH,
                        category="security",
                        path=dependency.path,
                        line=dependency.line,
                        message=f"{floor[1]} dependency '{dependency.name}' is pinned to {exact_version}; recommended floor is {floor[0]} or newer.",
                        recommendation="Upgrade flagged legacy dependencies and run a current SCA scanner before release.",
                    )
                )
        return findings

    def _scan_repo_shape(self, root: Path, files: list[CrawledFile]) -> list[Finding]:
        paths = {file.relative_path.as_posix() for file in files}
        names = {file.relative_path.name.lower() for file in files}
        lower_paths = {path.lower() for path in paths}
        findings: list[Finding] = []

        if not names.intersection(_README_NAMES):
            findings.append(_repo_finding("HYG001", "Missing README", Severity.MEDIUM, "Add a README with setup, usage, testing, and security notes."))
        if not names.intersection(_LICENSE_NAMES):
            findings.append(_repo_finding("HYG002", "Missing license", Severity.LOW, "Add a license file so reuse terms are explicit."))
        if ".gitignore" not in names:
            findings.append(_repo_finding("HYG003", "Missing .gitignore", Severity.LOW, "Add a .gitignore tailored to the project stack."))
        if not any(_has_path_hint(path, _TEST_HINTS) for path in lower_paths):
            findings.append(_repo_finding("HYG004", "No tests detected", Severity.MEDIUM, "Add automated tests and include the test command in documentation."))
        if not any(path.startswith(tuple(_CI_HINTS)) or path in _CI_HINTS for path in lower_paths):
            findings.append(_repo_finding("HYG007", "No CI configuration detected", Severity.LOW, "Add CI to run tests, linting, and security checks on every change."))
        if not names.intersection(_SECURITY_DOC_NAMES):
            findings.append(_repo_finding("SEC002", "Missing security policy", Severity.MEDIUM, "Add SECURITY.md with vulnerability reporting and supported versions."))

        manifests = {Path(path).name for path in paths}
        if manifests.intersection(_DEPENDENCY_MANIFESTS) and not _has_dependency_scanner(paths):
            findings.append(_repo_finding("SEC003", "Dependency manifest without scanner configuration", Severity.MEDIUM, "Enable Dependabot, Renovate, pip-audit, npm audit, or an equivalent dependency scanner."))
        for manifest, lock_candidates in _PACKAGE_MANIFESTS.items():
            if manifest in manifests and not manifests.intersection(lock_candidates):
                findings.append(
                    _repo_finding(
                        "HYG008",
                        f"Dependency manifest {manifest} has no lock file",
                        Severity.MEDIUM,
                        "Commit lock files for applications so builds are reproducible.",
                    )
                )

        if (root / ".git").exists() and not (root / ".git" / "shallow").exists():
            findings.append(
                Finding(
                    rule_id="HYG009",
                    title="Repository cloned with full history",
                    severity=Severity.INFO,
                    category="hygiene",
                    message="The audit ran on a full clone.",
                    recommendation="Use --depth 1 for large repositories when history is not needed.",
                )
            )
        return findings


def _iter_dependencies(files: list[CrawledFile]) -> Iterator[DependencySpec]:
    for crawled in files:
        if crawled.skipped_reason or crawled.text is None:
            continue
        path = crawled.relative_path.as_posix()
        name = crawled.relative_path.name
        if name == "requirements.txt":
            yield from _parse_requirements(path, crawled.text)
        elif name == "package.json":
            yield from _parse_package_json(path, crawled.text)
        elif name == "pyproject.toml":
            yield from _parse_pyproject(path, crawled.text)
        elif name == "pom.xml":
            yield from _parse_pom_xml(path, crawled.text)
        elif name == "composer.json":
            yield from _parse_composer_json(path, crawled.text)
        elif name == "Gemfile":
            yield from _parse_gemfile(path, crawled.text)
        elif name == "go.mod":
            yield from _parse_go_mod(path, crawled.text)


def _parse_requirements(path: str, text: str) -> Iterator[DependencySpec]:
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", ".", "/")):
            continue
        match = re.match(r"([A-Za-z0-9_.-]+)\s*(.*)", line)
        if not match:
            continue
        yield DependencySpec(match.group(1), match.group(2).strip() or "unversioned", path, line_number)


def _parse_package_json(path: str, text: str) -> Iterator[DependencySpec]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = payload.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, version_spec in dependencies.items():
            if isinstance(name, str) and isinstance(version_spec, str):
                yield DependencySpec(name, version_spec.strip(), path, _find_line_containing(text, f'"{name}"'))


def _parse_pyproject(path: str, text: str) -> Iterator[DependencySpec]:
    try:
        payload = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    project = payload.get("project", {})
    if isinstance(project, dict):
        for dependency in project.get("dependencies", []) or []:
            if isinstance(dependency, str):
                name, version_spec = _split_python_requirement(dependency)
                yield DependencySpec(name, version_spec, path, _find_line_containing(text, dependency))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for dependencies in optional.values():
                if isinstance(dependencies, list):
                    for dependency in dependencies:
                        if isinstance(dependency, str):
                            name, version_spec = _split_python_requirement(dependency)
                            yield DependencySpec(name, version_spec, path, _find_line_containing(text, dependency))
    poetry_dependencies = payload.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_dependencies, dict):
        for name, version_spec in poetry_dependencies.items():
            if name.lower() == "python":
                continue
            if isinstance(version_spec, str):
                yield DependencySpec(name, version_spec, path, _find_line_containing(text, name))
            elif isinstance(version_spec, dict) and isinstance(version_spec.get("version"), str):
                yield DependencySpec(name, version_spec["version"], path, _find_line_containing(text, name))


def _parse_pom_xml(path: str, text: str) -> Iterator[DependencySpec]:
    for match in re.finditer(r"<dependency>.*?<artifactId>(?P<name>[^<]+)</artifactId>.*?<version>(?P<version>[^<]+)</version>.*?</dependency>", text, re.DOTALL):
        yield DependencySpec(match.group("name"), match.group("version").strip(), path, text[: match.start()].count("\n") + 1)


def _parse_composer_json(path: str, text: str) -> Iterator[DependencySpec]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("require", "require-dev"):
        deps = payload.get(section, {})
        if not isinstance(deps, dict):
            continue
        for name, version_spec in deps.items():
            if isinstance(name, str) and name != "php" and isinstance(version_spec, str):
                yield DependencySpec(name, version_spec.strip(), path, _find_line_containing(text, f'"{name}"'))


def _parse_gemfile(path: str, text: str) -> Iterator[DependencySpec]:
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        match = re.match(r"""gem\s+['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]""", line)
        if match:
            yield DependencySpec(match.group(1), match.group(2).strip(), path, line_number)
        elif re.match(r"""gem\s+['"]([^'"]+)['"]""", line):
            name = re.match(r"""gem\s+['"]([^'"]+)['"]""", line).group(1)
            yield DependencySpec(name, "unversioned", path, line_number)


def _parse_go_mod(path: str, text: str) -> Iterator[DependencySpec]:
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        match = re.match(r"^require\s+(\S+)\s+(\S+)", line) or re.match(r"^\t?(\S+)\s+(v\S+)$", line)
        if match:
            name, version = match.group(1), match.group(2)
            if not name.startswith("//") and name != "require":
                yield DependencySpec(name, version.strip(), path, line_number)


def _split_python_requirement(dependency: str) -> tuple[str, str]:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)", dependency)
    if not match:
        return dependency.strip(), "unversioned"
    return match.group(1), match.group(2).strip() or "unversioned"


def _is_unpinned_dependency(version_spec: str) -> bool:
    spec = version_spec.strip()
    if not spec or spec == "unversioned" or spec.lower() == "latest":
        return True
    if spec.startswith(_PINNED_OPERATORS):
        return False
    if re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?", spec):
        return False
    return spec.startswith(_FLOATING_VERSION_PREFIXES) or any(operator in spec for operator in (">", "<", "*", "~", "^", ","))


def _extract_exact_version(version_spec: str) -> str | None:
    spec = version_spec.strip()
    if spec.startswith("==="):
        return spec[3:].strip()
    if spec.startswith("=="):
        return spec[2:].strip()
    if re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?", spec):
        return spec.lstrip("v")
    return None


def _compare_versions(current: str, floor: str) -> int:
    current_parts = _version_tuple(current)
    floor_parts = _version_tuple(floor)
    length = max(len(current_parts), len(floor_parts))
    current_parts += (0,) * (length - len(current_parts))
    floor_parts += (0,) * (length - len(floor_parts))
    if current_parts < floor_parts:
        return -1
    if current_parts > floor_parts:
        return 1
    return 0


def _version_tuple(version: str) -> tuple[int, ...]:
    numeric = re.match(r"v?(\d+(?:\.\d+)*)", version.strip())
    if not numeric:
        return (0,)
    return tuple(int(part) for part in numeric.group(1).split("."))


def _normalize_dependency_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _find_line_containing(text: str, needle: str) -> int | None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return line_number
    return None


def _repo_finding(rule_id: str, title: str, severity: Severity, recommendation: str) -> Finding:
    category = "security" if rule_id.startswith("SEC") else "hygiene"
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category, recommendation=recommendation)


def _has_path_hint(path: str, hints: set[str]) -> bool:
    parts = set(Path(path).parts)
    return bool(parts.intersection(hints)) or any(part.startswith("test_") or part.endswith("_test.py") for part in parts)


def _has_dependency_scanner(paths: set[str]) -> bool:
    lower_paths = {path.lower() for path in paths}
    scanner_hints = (
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
        "renovate.json",
        ".renovaterc",
        ".github/workflows/dependency-review.yml",
        ".github/workflows/dependency-review.yaml",
    )
    return any(hint in lower_paths for hint in scanner_hints)
