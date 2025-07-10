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
- **Memory System Overview**: `.claude/README.md` - Complete memory system guide and usage patterns ⭐ **NEW**
- **Primary Memory**: `.claude/CLAUDE.md` - Comprehensive project architecture and development guide
- **Implementation Status**: `.claude/memory.md` - Current implementation status and file references
- **Comprehensive Memory**: `.claude/memory-comprehensive.md` - Detailed complete project context ⭐ **NEW**
- **Current State Analysis**: `.claude/current-state-comprehensive.md` - Project metrics and status ⭐ **NEW**
- **Codebase Structure**: `.claude/codebase-structure-current.md` - Complete code organization ⭐ **NEW**
- **Architecture**: `.claude/architecture.md` - Detailed system architecture and design principles
- **External Libraries**: `.claude/external-libraries.md` - Local repository integration patterns
- **Strategic Planning**: `.claude/project-consolidation-plan.md`, `.claude/task-management.md`, `.claude/commit-consolidation-plan.md`
- **Session Documentation**: `.claude/session-consolidation-summary.md` - Session continuity patterns
- **Transaction Patterns**: `.claude/psycopg3-transaction-patterns.md` - Database best practices
- **Project Context**: Complete OAuth 2.1 + OIDC 1.0 authorization server (feature complete + consolidated)

## Development Focus
- **Quality Excellence**: Maintain 439/439 test success rate (100% pass rate achieved)
- **Real Integration Testing**: PostgreSQL testcontainers, no mocking, authentic patterns
- **Security First**: OAuth 2.1 + OIDC 1.0 compliance with defensive practices only
- **Production Architecture**: Scalable deployment with Docker and lifecycle management
- **Comprehensive Documentation**: Living documentation across `.claude/` memory system
- **Modern Python Patterns**: Async-first, type-safe, package-by-feature architecture

## Current Project Status (Feature Complete)
- **✅ OAuth 2.1 Authorization Server**: Complete RFC-compliant implementation with PKCE
- **✅ OpenID Connect 1.0**: Full OIDC layer with ID tokens, UserInfo, JWKS, Discovery
- **✅ API-First Admin System**: HTTP API + CLI with OAuth authentication
- **✅ Two-Layer Security Model**: Intrinsic authority + granular OAuth scopes
- **✅ Bootstrap System**: Complete IAM chicken-and-egg solution
- **✅ Test Excellence**: 439/439 tests passing with real integration patterns
- **✅ Production Ready**: Docker, monitoring, security hardening, lifecycle management
- **✅ Project Consolidation**: Complete documentation organization and memory system enhancement
- **🎯 Status**: All planned phases completed - project is feature complete + professionally consolidated

## Development Standards
- **Code Quality**: Type annotations, Pydantic validation, async patterns
- **Testing**: Real database integration, no shortcuts, comprehensive coverage
- **Security**: OWASP compliance, secure defaults, threat model awareness
- **Architecture**: Clean layered design, dependency injection, pluggable components
- **Documentation**: API-first documentation, architectural decision records