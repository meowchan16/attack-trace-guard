"""
Pytest configuration and compatibility fixtures.
"""

import httpx

# Compatibility patch: httpx>=0.28.0 (required by google-genai) removed the deprecated
# 'app' argument from Client.__init__, which Starlette 0.36's TestClient still passes.
_orig_httpx_client_init = httpx.Client.__init__


def _patched_httpx_client_init(self, *args, **kwargs):
    kwargs.pop("app", None)
    return _orig_httpx_client_init(self, *args, **kwargs)


httpx.Client.__init__ = _patched_httpx_client_init
