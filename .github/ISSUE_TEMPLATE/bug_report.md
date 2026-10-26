---
name: Bug report
about: AgentPreflight produced a wrong or unexpected result
labels: bug
---

## What happened?

<!-- A clear description of the bug. -->

## What did you expect?

<!-- What should have happened instead? -->

## How to reproduce

```bash
# commands you ran, e.g.
agentpreflight scan .
```

<!-- Minimal input file(s) that trigger the issue.
     NEVER paste real credentials — replace values with synthetic ones
     (e.g. AKIAIOSFODNN7EXAMPLE <!-- agentpreflight: allow -->, ghp_ + 36 characters of "a"). -->

```text
# file content that triggers it (synthetic values only!)
```

## Environment

- AgentPreflight version: output of `agentpreflight version`
- Python version:
- OS:
- Output of `agentpreflight doctor` (if relevant):

## Rule involved (if applicable)

<!-- Rule ID from the finding, e.g. APF-SEC-020 -->

## Is this a false positive?

<!-- If a finding is wrong, include the finding line with the secret masked. -->
