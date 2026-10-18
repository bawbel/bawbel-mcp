# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** Report privately, using either:

- GitHub private vulnerability reporting: the "Report a vulnerability" button under this
  repository's Security tab.
- Email: **bawbel.io@gmail.com**, subject `SECURITY: bawbel-mcp [brief description]`.

Include the tool name, the bawbel-mcp and bawbel-scanner versions, the MCP client, and the
tool call that reproduces it.

## Scope

In scope: this repository, the bawbel-mcp server (`bawbel_mcp/`) and its tool surface:
the tools, their arguments, and what they read, return, or reach over the network.

Out of scope, report to the relevant repository instead:

- Detection rules, false positives, and missed findings: [bawbel/scanner](https://github.com/bawbel/scanner)
- AVE record content or the AVE schema: [aveproject/ave](https://github.com/aveproject/ave), an
  independent project. Contact: aveproject.org@gmail.com
