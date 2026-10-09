"""overreach - audit Microsoft Entra ID for over-permissioned human identities.

Deterministic and explainable: every finding records the evidence and its
confidence, and nothing uses an LLM in the verdict path. Read-only by design.
Companion to nhi-scan (non-human / agent identities); see OP6 for the bridge.
"""

__version__ = "0.1.0"
