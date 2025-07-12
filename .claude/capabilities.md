# Claude Capabilities Configuration

## Enabled Tools
- **Read**: File reading and analysis for codebase exploration
- **Write**: File creation and modification for documentation and code
- **TodoWrite**: Task management and progress tracking
- **Bash**: Command execution for development tasks (tests, builds, git operations)
- **Edit/MultiEdit**: Code editing and refactoring with precision
- **Grep/Glob**: Advanced code search and pattern matching
- **LS**: Directory listing and exploration
- **Task**: Complex analysis and search operations for large codebases
- **WebFetch/WebSearch**: Research and documentation access

## Memory Management
**See `.claude/README.md` for complete memory system guide and usage patterns.**

**Primary References:**
- **`.claude/CLAUDE.md`** - Primary project memory and development guide
- **`.claude/memory.md`** - Implementation status and detailed file references
- **`.claude/architecture.md`** - System architecture and design principles
- **`.claude/external-libraries.md`** - Local repository integration patterns

**Strategic Planning:**
- **`.claude/project-consolidation-plan.md`** - Consolidation strategy
- **`.claude/task-management.md`** - TodoWrite workflow patterns
- **`.claude/commit-consolidation-plan.md`** - Git history management

**Technical References:**
- **`.claude/codebase-structure-current.md`** - Complete code organization
- **`.claude/psycopg3-transaction-patterns.md`** - Database best practices
- **`.claude/session-consolidation-summary.md`** - Session continuity patterns

**Project Context**: Complete OAuth 2.1 + OIDC 1.0 authorization server (feature complete + consolidated)

## Development Focus
- **Quality Excellence**: Maintain 439/439 test success rate (100% pass rate achieved)
- **Real Integration Testing**: PostgreSQL testcontainers, no mocking, authentic patterns
- **Security First**: OAuth 2.1 + OIDC 1.0 compliance with defensive practices only
- **Production Architecture**: Scalable deployment with Docker and lifecycle management
- **Comprehensive Documentation**: Living documentation across `.claude/` memory system
- **Modern Python Patterns**: Async-first, type-safe, package-by-feature architecture

## Current Project Status (Feature Complete)
**See `.claude/memory.md` for detailed implementation status and next steps.**

**Core Completed Features:**
- **✅ OAuth 2.1 + OIDC 1.0**: Complete authorization server implementation
- **✅ Test Excellence**: 439/439 tests passing with real integration patterns
- **✅ Production Ready**: Docker, monitoring, security hardening
- **✅ Project Consolidation**: Complete documentation organization

**🎯 Status**: All planned phases completed - project is feature complete + professionally consolidated

## Development Standards
- **Code Quality**: Type annotations, Pydantic validation, async patterns
- **Testing**: Real database integration, no shortcuts, comprehensive coverage
- **Security**: OWASP compliance, secure defaults, threat model awareness
- **Architecture**: Clean layered design, dependency injection, pluggable components
- **Documentation**: API-first documentation, architectural decision records