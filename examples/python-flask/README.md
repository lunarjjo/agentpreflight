# Example: Python service that passes AgentPreflight

A minimal Flask-style layout that demonstrates the intended hygiene:

- `.env.example` (placeholder values only) — the real `.env` is gitignored
- secrets read from environment variables
- TLS verification left enabled
- `requirements.txt` pinned for reproducible builds

Run the scanner against this directory:

```bash
agentpreflight scan .            # exits 0 — no high findings
```

The example intentionally contains no real or synthetic-looking secrets,
so it needs no suppression entries at all.
