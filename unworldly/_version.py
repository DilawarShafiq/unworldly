"""Single source of truth for the Unworldly version.

Read by ``unworldly/__init__.py``, ``cli.py``, ``session.py`` and — via
``[tool.setuptools.dynamic]`` in ``pyproject.toml`` — by the build backend, so
the version is defined in exactly one place. Bump it here only.
"""

__version__ = "0.6.0"
