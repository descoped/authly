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
**See `.claude/CLAUDE.md` for complete memory system organization and usage patterns.**

**Primary References:**
- **`.claude/CLAUDE.md`** - **PRIMARY ENTRY POINT** - Complete project memory and development guide
- **`.claude/implementation-status.md`** - Current implementation status and detailed progress tracking
- **`.claude/architecture.md`** - System architecture and design principles  
- **`.claude/codebase-structure.md`** - Complete project structure with metrics
- **`docs/README.md`** - Complete documentation index with 18 guides

**Development Workflows:**
- **`.claude/task-management.md`** - TodoWrite workflow patterns and enterprise project management

**Historical Knowledge:**
- **`.claude/evolution/`** - Complete implementation history (for learning purposes only)
- **`.claude/roadmap/`** - Future features and strategic roadmaps

**Project Context**: Production-ready OAuth 2.1 + OIDC 1.0 authorization server with comprehensive documentation

## Development Focus
- **Quality Excellence**: Maintain 510/510 test success rate (100% pass rate achieved)
- **Real Integration Testing**: PostgreSQL testcontainers, no mocking, authentic patterns
- **Security First**: OAuth 2.1 + OIDC 1.0 compliance with defensive practices only
- **Production Architecture**: Scalable deployment with Docker and lifecycle management
- **Comprehensive Documentation**: Living documentation across `.claude/` memory system
- **Modern Python Patterns**: Async-first, type-safe, package-by-feature architecture

## Current Project Status (Production Ready)
**See `ai_docs/TODO.md` for current tasks and implementation priorities.**

**Core Completed Features:**
- **✅ OAuth 2.1 + OIDC 1.0**: Complete authorization server implementation
- **✅ Test Excellence**: 510/510 tests passing with real integration patterns
- **✅ Production Ready**: Docker, monitoring, security hardening
- **✅ Documentation**: 18 comprehensive guides covering all aspects
- **✅ GDPR Foundation**: Privacy compliance analysis and implementation guide

**🎯 Status**: Enterprise production ready - remaining tasks focus on advanced GDPR features

## Development Standards
- **Code Quality**: Type annotations, Pydantic validation, async patterns
- **Testing**: Real database integration, no shortcuts, comprehensive coverage
- **Security**: OWASP compliance, secure defaults, threat model awareness
- **Architecture**: Clean layered design, dependency injection, pluggable components
- **Documentation**: API-first documentation, architectural decision records