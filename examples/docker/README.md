# Example: hardened container build

The Dockerfile demonstrates the container rules AgentPreflight checks:

- non-root `USER`
- pinned base image digest
- no `--privileged`, no remote-script piping into shells
- `.dockerignore` keeps local secrets out of build context

Run:

```bash
agentpreflight scan .    # exits 0
```
