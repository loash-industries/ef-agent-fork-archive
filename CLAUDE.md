# CLAUDE.md — ZeroClaw (Claude Code)

> **Shared instructions live in [`AGENTS.md`](./AGENTS.md).**
> This file contains only Claude Code-specific directives.

## Claude Code Settings

@AGENTS.md

The import above loads `AGENTS.md` into context, so there is no need to open it again. Add only Claude Code-specific notes below.

## Hooks

_No custom hooks defined yet._

## Slash Commands

_No custom slash commands defined yet._

## Cortex

**MCP Server:** `https://cortex-relay-dev-api.trinary.exchange/mcp` — service id `ef-agent`.

1. At session start call `get_conventions` with `scope: "general"`.
2. Before a task, call `search_context` with the task and `service_id: "ef-agent"`.
3. Before every commit, call `chronicle_changes` with `service_id: "ef-agent"`, prepend the returned entry to `.cortex/changelog.md`, and apply any `overviewEdits` to `.cortex/overview.md`.
