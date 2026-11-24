"""Supply-chain checks on package install commands (spec: specs/flag-0.9/spec.md, F2).

Offline and deterministic: install commands are parsed into package names, which
are compared with a bundled list of well-known packages per ecosystem to spot
likely typosquats (``reqeusts`` for ``requests``). No registry lookups are made, so
"this package was published yesterday" cannot be checked; docs say so.
"""

from __future__ import annotations

import re

from .types import RiskLevel

# Well-known packages per ecosystem (names normalised: lower case, "_" and "." as "-").
POPULAR: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        [
            "requests",
            "urllib3",
            "numpy",
            "pandas",
            "django",
            "flask",
            "fastapi",
            "pydantic",
            "sqlalchemy",
            "boto3",
            "botocore",
            "setuptools",
            "wheel",
            "pip",
            "six",
            "python-dateutil",
            "pytz",
            "certifi",
            "idna",
            "charset-normalizer",
            "click",
            "jinja2",
            "markupsafe",
            "werkzeug",
            "pyyaml",
            "attrs",
            "packaging",
            "cryptography",
            "cffi",
            "pycparser",
            "rsa",
            "pyasn1",
            "jmespath",
            "s3transfer",
            "awscli",
            "google-api-core",
            "protobuf",
            "grpcio",
            "typing-extensions",
            "tqdm",
            "scipy",
            "matplotlib",
            "pillow",
            "scikit-learn",
            "tensorflow",
            "torch",
            "torchvision",
            "keras",
            "transformers",
            "tokenizers",
            "huggingface-hub",
            "openai",
            "anthropic",
            "langchain",
            "langchain-core",
            "llama-index",
            "tiktoken",
            "httpx",
            "httpcore",
            "h11",
            "anyio",
            "sniffio",
            "aiohttp",
            "multidict",
            "yarl",
            "frozenlist",
            "aiosignal",
            "async-timeout",
            "uvicorn",
            "gunicorn",
            "starlette",
            "celery",
            "redis",
            "kombu",
            "psycopg2",
            "psycopg2-binary",
            "pymongo",
            "mysqlclient",
            "pymysql",
            "beautifulsoup4",
            "lxml",
            "soupsieve",
            "selenium",
            "scrapy",
            "pytest",
            "pytest-cov",
            "coverage",
            "mock",
            "tox",
            "black",
            "flake8",
            "pylint",
            "mypy",
            "ruff",
            "isort",
            "pre-commit",
            "virtualenv",
            "poetry",
            "pipenv",
            "rich",
            "colorama",
            "tabulate",
            "docutils",
            "sphinx",
            "jsonschema",
            "simplejson",
            "ujson",
            "orjson",
            "pyjwt",
            "oauthlib",
            "requests-oauthlib",
            "paramiko",
            "fabric",
            "invoke",
            "psutil",
            "watchdog",
            "pexpect",
            "ptyprocess",
            "decorator",
            "wrapt",
            "cachetools",
            "filelock",
            "platformdirs",
            "pluggy",
            "py",
            "iniconfig",
            "tomli",
            "toml",
            "greenlet",
            "gevent",
            "eventlet",
            "websocket-client",
            "websockets",
            "openpyxl",
            "xlrd",
            "xlsxwriter",
            "pyarrow",
            "polars",
            "dask",
            "numba",
            "networkx",
            "sympy",
            "nltk",
            "spacy",
            "gensim",
            "opencv-python",
            "imageio",
            "seaborn",
            "plotly",
            "bokeh",
            "dash",
            "streamlit",
            "gradio",
            "jupyter",
            "notebook",
            "ipython",
            "ipykernel",
            "nbformat",
            "markdown",
            "pygments",
            "regex",
            "chardet",
            "python-dotenv",
            "dotenv",
            "marshmallow",
            "alembic",
            "peewee",
            "tortoise-orm",
            "moto",
            "boto",
            "jinja",
            "pytest-mock",
            "pytest-xdist",
            "pytest-asyncio",
            "flask-cors",
            "attr",
        ]
    ),
    "npm": frozenset(
        [
            "react",
            "react-dom",
            "vue",
            "angular",
            "svelte",
            "next",
            "nuxt",
            "express",
            "koa",
            "fastify",
            "hapi",
            "lodash",
            "underscore",
            "axios",
            "node-fetch",
            "request",
            "moment",
            "dayjs",
            "date-fns",
            "chalk",
            "commander",
            "yargs",
            "inquirer",
            "debug",
            "dotenv",
            "uuid",
            "nanoid",
            "classnames",
            "prop-types",
            "redux",
            "react-redux",
            "mobx",
            "zustand",
            "rxjs",
            "typescript",
            "ts-node",
            "tslib",
            "webpack",
            "webpack-cli",
            "vite",
            "rollup",
            "esbuild",
            "parcel",
            "babel-core",
            "@babel/core",
            "@babel/preset-env",
            "eslint",
            "prettier",
            "jest",
            "mocha",
            "chai",
            "sinon",
            "cypress",
            "playwright",
            "puppeteer",
            "jquery",
            "bootstrap",
            "tailwindcss",
            "postcss",
            "autoprefixer",
            "sass",
            "less",
            "styled-components",
            "emotion",
            "socket.io",
            "ws",
            "mongoose",
            "mongodb",
            "sequelize",
            "prisma",
            "pg",
            "mysql",
            "mysql2",
            "redis",
            "ioredis",
            "jsonwebtoken",
            "bcrypt",
            "bcryptjs",
            "passport",
            "cors",
            "helmet",
            "body-parser",
            "cookie-parser",
            "multer",
            "morgan",
            "winston",
            "pino",
            "nodemon",
            "pm2",
            "concurrently",
            "cross-env",
            "rimraf",
            "glob",
            "minimist",
            "fs-extra",
            "mkdirp",
            "semver",
            "async",
            "bluebird",
            "q",
            "colors",
            "cheerio",
            "marked",
            "highlight.js",
            "three",
            "d3",
            "chart.js",
            "graphql",
            "apollo-server",
            "@apollo/client",
            "firebase",
            "aws-sdk",
            "@aws-sdk/client-s3",
            "openai",
            "@anthropic-ai/sdk",
            "langchain",
            "zod",
            "yup",
            "joi",
            "ajv",
            "immer",
            "ramda",
            "core-js",
            "regenerator-runtime",
            "preact",
            "vitest",
            "nest",
            "inferno",
        ]
    ),
    "cargo": frozenset(
        """
        serde serde_json tokio rand clap regex log env_logger anyhow thiserror reqwest
        hyper actix-web axum chrono lazy_static once_cell futures itertools rayon
        """.replace("_", "-").split()
    ),
    "gem": frozenset(
        ["rails", "rake", "bundler", "rspec", "nokogiri", "devise", "puma", "sidekiq", "pry", "rubocop", "json"]
    ),
}

# install command -> ecosystem. Order matters: more specific first.
_INSTALLERS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\buv\s+pip\s+install\b(.*)"), "pypi"),
    (re.compile(r"\buv\s+add\b(.*)"), "pypi"),
    (re.compile(r"\bpip3?\s+install\b(.*)"), "pypi"),
    (re.compile(r"\bpython3?\s+-m\s+pip\s+install\b(.*)"), "pypi"),
    (re.compile(r"\bpoetry\s+add\b(.*)"), "pypi"),
    (re.compile(r"\bpipx\s+install\b(.*)"), "pypi"),
    (re.compile(r"\bnpm\s+(?:install|i|add)\b(.*)"), "npm"),
    (re.compile(r"\byarn\s+add\b(.*)"), "npm"),
    (re.compile(r"\bpnpm\s+(?:add|install|i)\b(.*)"), "npm"),
    (re.compile(r"\bbun\s+add\b(.*)"), "npm"),
    (re.compile(r"\bcargo\s+(?:add|install)\b(.*)"), "cargo"),
    (re.compile(r"\bgem\s+install\b(.*)"), "gem"),
]
# options that consume the next token (so it isn't read as a package name)
_VALUE_OPTIONS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "--prefix"}
_INDEX_OPTIONS = re.compile(r"(--index-url|--extra-index-url|-i\b|--registry|--source)")
_OUTSIDE_REGISTRY = re.compile(r"(://|^git\+|^github:|\.(tar\.gz|tgz|whl|zip)$)")


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _strip_version(token: str, ecosystem: str) -> str:
    if ecosystem == "npm":
        if token.startswith("@"):
            scope, _, rest = token.partition("/")
            return f"{scope}/{rest.split('@', 1)[0]}"
        return token.split("@", 1)[0]
    return re.split(r"[=<>!~\[;@ ]", token, maxsplit=1)[0]


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance (insert, delete, substitute, swap neighbours)."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[len(a)][len(b)]


def lookalike(name: str, ecosystem: str) -> str | None:
    """The well-known package ``name`` imitates, if it is a near miss of one."""
    known = POPULAR.get(ecosystem, frozenset())
    n = normalise(name)
    if len(n) <= 3 or n in known:
        return None
    for popular in sorted(known):
        limit = 1 if len(popular) <= 5 else 2
        if abs(len(popular) - len(n)) <= limit and edit_distance(n, popular) <= limit:
            return popular
    return None


def parse_install(command: str) -> tuple[str, list[str], list[str], bool] | None:
    """(ecosystem, package names, outside-registry specs, custom index?) or None."""
    for pattern, ecosystem in _INSTALLERS:
        match = pattern.search(command)
        if not match:
            continue
        rest = match.group(1)
        custom_index = bool(_INDEX_OPTIONS.search(rest))
        names: list[str] = []
        outside: list[str] = []
        skip_next = False
        for token in rest.split():
            token = token.strip("'\"")
            if skip_next:
                skip_next = False
                continue
            if token in _VALUE_OPTIONS or _INDEX_OPTIONS.fullmatch(token):
                skip_next = True
                continue
            if token.startswith("-") or token in {".", ".."} or token.startswith(("./", "../", "/")):
                continue
            if _OUTSIDE_REGISTRY.search(token):
                outside.append(token)
                continue
            name = _strip_version(token, ecosystem)
            if name:
                names.append(name)
        return ecosystem, names, outside, custom_index
    return None


def check_install(command: str) -> list[tuple[RiskLevel, str]]:
    """Supply-chain findings for one command: (level, message) pairs, empty if none."""
    parsed = parse_install(command)
    if parsed is None:
        return []
    ecosystem, names, outside, custom_index = parsed
    findings: list[tuple[RiskLevel, str]] = []
    for name in names:
        target = lookalike(name, ecosystem)
        if target is not None:
            findings.append(
                (RiskLevel.DANGER, f"Possible typosquat: installed `{name}`, which looks like `{target}` ({ecosystem})")
            )
    for spec in outside:
        findings.append((RiskLevel.CAUTION, f"Package installed from outside the registry: `{spec}`"))
    if custom_index:
        findings.append((RiskLevel.CAUTION, f"Package installed from a custom index or registry ({ecosystem})"))
    return findings
