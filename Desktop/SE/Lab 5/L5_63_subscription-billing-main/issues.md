# Lab 5: Static Code Analysis — Issue Documentation

| Issue | Type | Line(s) | Description | Fix Approach |
|---|---|---|---|---|
| Deprecated cryptography library warning | Security — High | 8 | Bandit flags the `Crypto.Cipher.AES` import as a deprecated cryptography-library warning. | Replace with a maintained cryptography library and use secure encryption practices. |
| Potential HTML injection (XSS) | Security — Medium | 86 | Mako renders user-provided content as HTML, which may allow malicious HTML injection. | HTML-escape template variables before rendering. |
| Hardcoded webhook secret | Security — Low | 14 | A webhook secret is stored directly in the source code. | Load the secret from an environment variable. |
| Insecure random coupon generation | Security — Low | 67 | The standard `random` module is unsuitable for security-sensitive random values. | Use the `secrets` module. |
| Assertion used for validation | Security / Reliability — Low | 85 | An `assert` statement may be removed when Python runs in optimized mode. | Replace it with explicit input validation and raise `ValueError`. |
| Broad code-quality and style issues | Code Quality | Multiple | Pylint and Flake8 report missing docstrings, unused imports, naming violations and long lines. | Follow PEP 8, remove unused imports, add docstrings and use snake_case names.