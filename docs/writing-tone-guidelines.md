# Documentation Writing & Tone Guidelines

## Overview
These guidelines help maintain a consistent, professional tone across Authly documentation while avoiding marketing language and unnecessary hyperbole.

## Key Principles

### 1. Be Precise, Not Grandiose
- ✅ **Good**: "OAuth 2.1 authorization server with admin CLI"
- ❌ **Avoid**: "Comprehensive OAuth 2.1 authorization server with powerful admin CLI"
- ✅ **Good**: "Full test coverage"
- ❌ **Avoid**: "Comprehensive test suite"

### 2. Use Technical Accuracy
Replace vague marketing terms with specific technical descriptions:
- Instead of "comprehensive" → use "complete", "full", "detailed", or specify what's included
- Instead of "powerful" → describe specific capabilities
- Instead of "enterprise-grade" → list specific enterprise features
- Instead of "production-ready" → specify what makes it suitable for production

### 3. Avoid Redundant Modifiers
Many adjectives add no value:
- "Complete control" → "Control"
- "Full support" → "Support"
- "Comprehensive guide" → "Guide" or "Detailed guide" if emphasis needed
- "Powerful features" → "Features" or describe what they do

### 4. Be Factual, Not Promotional
Documentation should inform, not sell:
- ✅ **Good**: "Supports OAuth 2.1 authorization code flow with PKCE"
- ❌ **Avoid**: "Industry-leading OAuth 2.1 implementation"
- ✅ **Good**: "700+ tests with database integration"
- ❌ **Avoid**: "Best-in-class test coverage"

## Common Replacements

| Avoid | Use Instead |
|-------|-------------|
| Comprehensive | Complete, Full, Detailed, Extensive (only when necessary) |
| Powerful | (Describe specific capabilities) |
| Enterprise-grade | Enterprise features: [list them] |
| Production-ready | Production features: monitoring, logging, error handling |
| Robust | Reliable, Tested, Stable |
| Cutting-edge | Modern, Current, Latest |
| Industry-leading | (Remove or cite specific benchmarks) |
| Best-in-class | (Remove or provide comparison data) |
| Revolutionary | New, Updated, Redesigned |
| State-of-the-art | Modern, Current |

## Examples

### Before
"Authly is a comprehensive, production-ready OAuth 2.1 authorization server with powerful admin tools and enterprise-grade security features."

### After
"Authly is an OAuth 2.1 authorization server with admin CLI, rate limiting, token revocation, and audit logging."

### Before
"This comprehensive guide provides complete documentation for all powerful features."

### After
"This guide documents all features and usage patterns."

### Before
"Our robust, enterprise-grade architecture ensures maximum performance."

### After
"The async architecture handles 10,000+ requests/second with 99.9% uptime."

## Writing Checklist

Before publishing documentation:
- [ ] Remove unnecessary adjectives (comprehensive, powerful, robust)
- [ ] Replace marketing terms with technical descriptions
- [ ] Verify claims with data or examples
- [ ] Focus on what the software does, not how impressive it is
- [ ] Use active voice and direct language
- [ ] Keep sentences concise and clear

## Tone Examples

### Technical Documentation
**Good**: "The OAuth token endpoint validates PKCE parameters and returns JWT tokens."
**Poor**: "Our powerful OAuth token endpoint comprehensively validates all PKCE parameters."

### Feature Descriptions
**Good**: "Admin CLI manages OAuth clients, scopes, and users."
**Poor**: "Comprehensive admin CLI provides powerful management capabilities."

### Performance Claims
**Good**: "Handles 12,500 password authentications per second on 8-core hardware."
**Poor**: "Industry-leading performance with comprehensive optimization."

## Summary

Good technical documentation:
- States facts clearly
- Provides specific details
- Avoids unnecessary adjectives
- Focuses on utility over impressiveness
- Uses measurements instead of superlatives
- Describes features by what they do, not how "powerful" they are

Remember: If every feature is "comprehensive" and "powerful," then none of them are. Let the technical capabilities speak for themselves.