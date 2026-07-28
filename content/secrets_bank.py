"""
Банк СИНТЕТИЧЕСКИХ секретов для редких аномалий «утечка секрета».

Значения выглядят структурно правдоподобно (формат как у настоящих
ключей/токенов), но НЕ являются валидными — это безопасные тестовые данные
для обучения детектора. Также есть benign-плейсхолдеры (env.example,
тестовые ключи) — «похоже на секрет, но это норма» — для усложнения ML.
"""
import random
import string
import base64


def _rand(n, alpha=string.ascii_letters + string.digits):
    return "".join(random.choice(alpha) for _ in range(n))


def _hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


# ----------------------------------------------------------------------
# Настоящие на вид секреты (синтетические)
# ----------------------------------------------------------------------
def aws_key():
    return {
        "type": "aws_access_key",
        "lines": [
            f"AWS_ACCESS_KEY_ID=AKIA{_rand(16, string.ascii_uppercase + string.digits)}",
            f"AWS_SECRET_ACCESS_KEY={_rand(40)}",
        ],
    }


def gcp_key():
    pk = "-----BEGIN PRIVATE KEY-----\\n" + _rand(64) + "\\n-----END PRIVATE KEY-----\\n"
    return {
        "type": "gcp_service_account",
        "lines": [
            '{',
            '  "type": "service_account",',
            f'  "project_id": "soc-prod-{_hex(6)}",',
            f'  "private_key_id": "{_hex(40)}",',
            f'  "private_key": "{pk}",',
            '  "client_email": "svc-deploy@soc-prod.iam.gserviceaccount.com"',
            '}',
        ],
    }


def private_key():
    body = "\n".join(_rand(64) for _ in range(6))
    return {
        "type": "ssh_private_key",
        "lines": ["-----BEGIN RSA PRIVATE KEY-----", body, "-----END RSA PRIVATE KEY-----"],
    }


def jwt_token():
    h = base64.b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.b64encode(("{\"sub\":\"svc\",\"k\":\"" + _rand(20) + "\"}").encode()).decode().rstrip("=")
    return {"type": "jwt", "lines": [f"API_JWT={h}.{p}.{_rand(43)}"]}


def db_url():
    return {
        "type": "db_connection_string",
        "lines": [f"DATABASE_URL=postgres://soc_admin:{_rand(18)}@db.prod.soc.local:5432/siem"],
    }


def slack_token():
    return {"type": "slack_token",
            "lines": [f"SLACK_BOT_TOKEN=xoxb-{_hex(12)}-{_hex(12)}-{_rand(24)}"]}


def generic_api_key():
    return {"type": "api_key",
            "lines": [f"PROD_API_KEY={_rand(48)}", f"PROD_API_SECRET={_hex(64)}"]}


def base64_blob():
    raw = (_rand(220)).encode()
    return {"type": "base64_blob",
            "lines": ["EXPORT_DATA_B64=" + base64.b64encode(raw).decode()]}


_REAL = [aws_key, gcp_key, private_key, jwt_token, db_url, slack_token, generic_api_key]


def random_secret():
    """Случайный реалистичный синтетический секрет: dict(type, lines)."""
    return random.choice(_REAL)()


def secret_env_file(secret=None):
    """Содержимое .env-подобного файла с настоящим на вид секретом."""
    secret = secret or random_secret()
    header = [
        "# production environment — DO NOT COMMIT",
        "ENV=production",
        f"SERVICE=soc-{random.choice(['ingest','api','worker'])}",
    ]
    return secret["type"], "\n".join(header + secret["lines"]) + "\n"


# ----------------------------------------------------------------------
# Benign-плейсхолдеры (похоже на секрет, но это НОРМА — для усложнения ML)
# ----------------------------------------------------------------------
def benign_env_example():
    return ("env_example",
            "# .env.example — шаблон, реальные значения берутся из vault\n"
            "ENV=production\n"
            "AWS_ACCESS_KEY_ID=<your-key-here>\n"
            "AWS_SECRET_ACCESS_KEY=changeme\n"
            "DATABASE_URL=postgres://user:password@localhost:5432/db\n"
            "API_KEY=REPLACE_ME\n")


def benign_test_key():
    return ("test_fixture",
            "# tests/fixtures — заведомо фейковые значения для юнит-тестов\n"
            "TEST_AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "TEST_TOKEN=example-token-0000-not-a-secret\n"
            "EXPECTED_HASH=0000000000000000000000000000000000000000\n")


def benign_base64_icon():
    raw = b"PNGICON" + bytes(random.randint(0, 255) for _ in range(120))
    return ("asset_base64",
            "ICON_B64=" + base64.b64encode(raw).decode() + "\n")


_BENIGN = [benign_env_example, benign_test_key, benign_base64_icon]


def random_benign_lookalike():
    """Похожий на секрет, но безопасный артефакт (is_anomaly=false)."""
    return random.choice(_BENIGN)()
