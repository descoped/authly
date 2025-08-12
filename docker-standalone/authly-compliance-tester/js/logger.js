/**
 * Unified Logger for Authly Compliance Tester
 * Provides standardized logging with display and clipboard formats
 */

class Logger {
    constructor(container = null) {
        this.logs = [];
        this.displayLogs = [];
        this.detailedLogs = [];
        this.container = container || document.getElementById('executionLog');
        this.maxLogs = 1000;
        this.sessionId = this.generateSessionId();
        this.startTime = new Date();
        
        // Test result tracking
        this.testResults = {
            total: 0,
            passed: 0,
            failed: 0,
            failures: [],
            duration: 0
        };
        
        // Logging configuration
        this.config = {
            logLevel: 'info', // info, debug, verbose
            showSuccesses: false, // Only show summary for passed tests
            maxHttpBodyLength: 200,
            maxHttpHeadersCount: 5
        };
    }

    generateSessionId() {
        return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    /**
     * Core logging method with multiple format support
     */
    log(message, level = 'info', metadata = {}) {
        const timestamp = new Date();
        const relativeTime = (timestamp - this.startTime) / 1000;
        
        // Create log entry
        const logEntry = {
            timestamp,
            relativeTime,
            level,
            message,
            metadata,
            sessionId: this.sessionId
        };
        
        // Store in memory
        this.logs.push(logEntry);
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }
        
        // Format for display (user-friendly)
        const displayMessage = this.formatForDisplay(logEntry);
        this.displayLogs.push(displayMessage);
        
        // Format for clipboard (detailed)
        const detailedMessage = this.formatForClipboard(logEntry);
        this.detailedLogs.push(detailedMessage);
        
        // Update UI if container exists
        if (this.container) {
            this.appendToUI(displayMessage, level);
        }
        
        // Console output for debugging
        this.logToConsole(logEntry);
        
        return logEntry;
    }

    /**
     * Format log entry for user-friendly display
     */
    formatForDisplay(entry) {
        const levelIcon = this.getLevelIcon(entry.level);
        
        // For test results, use compact format
        if (entry.level === 'test-pass' && !this.config.showSuccesses) {
            return `${levelIcon} ${entry.message}`;
        }
        
        if (entry.level === 'test-fail') {
            // Enhanced failure format
            let display = `${levelIcon} ${entry.message}`;
            if (entry.metadata.error) {
                display += `\n   └─ ${entry.metadata.error}`;
            }
            if (entry.metadata.expected && entry.metadata.actual) {
                display += `\n   Expected: ${entry.metadata.expected}`;
                display += `\n   Actual: ${entry.metadata.actual}`;
            }
            return display;
        }
        
        // Compact HTTP request format
        if (entry.level === 'http') {
            const method = entry.metadata.request?.method || 'GET';
            const url = entry.metadata.request?.url || '';
            const status = entry.metadata.response?.status;
            return `→ ${method} ${url.replace(/^.*?\/api/, '/api')}\n← ${status ? status + ':' : ''} ${entry.message.split('→')[1] || ''}`;
        }
        
        // Default format
        return `${levelIcon} ${entry.message}`;
    }

    /**
     * Format log entry for detailed clipboard export
     */
    formatForClipboard(entry) {
        const timestamp = entry.timestamp.toISOString();
        const lines = [
            `[${timestamp}] [${entry.level.toUpperCase()}] ${entry.message}`
        ];
        
        // Add all metadata
        if (Object.keys(entry.metadata).length > 0) {
            lines.push('  Metadata:');
            
            // HTTP Request details
            if (entry.metadata.request) {
                const req = entry.metadata.request;
                lines.push(`    Request:`);
                lines.push(`      Method: ${req.method || 'GET'}`);
                lines.push(`      URL: ${req.url}`);
                if (req.headers) {
                    lines.push(`      Headers:`);
                    Object.entries(req.headers).forEach(([key, value]) => {
                        // Mask sensitive headers
                        if (key.toLowerCase() === 'authorization') {
                            value = value.substring(0, 20) + '...[masked]';
                        }
                        lines.push(`        ${key}: ${value}`);
                    });
                }
                if (req.body) {
                    lines.push(`      Body: ${this.formatBody(req.body)}`);
                }
            }
            
            // HTTP Response details
            if (entry.metadata.response) {
                const res = entry.metadata.response;
                lines.push(`    Response:`);
                lines.push(`      Status: ${res.status} ${res.statusText || ''}`);
                if (res.headers) {
                    lines.push(`      Headers:`);
                    Object.entries(res.headers).forEach(([key, value]) => {
                        lines.push(`        ${key}: ${value}`);
                    });
                }
                if (res.body) {
                    lines.push(`      Body: ${this.formatBody(res.body)}`);
                }
            }
            
            // Additional metadata
            Object.entries(entry.metadata).forEach(([key, value]) => {
                if (!['request', 'response', 'endpoint', 'status'].includes(key)) {
                    lines.push(`    ${key}: ${JSON.stringify(value, null, 2)}`);
                }
            });
        }
        
        return lines.join('\n');
    }

    /**
     * Format body content for logging with smart truncation
     */
    formatBody(body) {
        if (typeof body === 'string') {
            if (body.length > this.config.maxHttpBodyLength) {
                return body.substring(0, this.config.maxHttpBodyLength) + '...[truncated]';
            }
            return body;
        }
        if (typeof body === 'object') {
            const str = JSON.stringify(body, null, 2);
            if (str.length > this.config.maxHttpBodyLength) {
                return JSON.stringify(body) + '...[formatted]';
            }
            return str;
        }
        return String(body);
    }

    /**
     * Filter headers to show only relevant ones
     */
    filterHeaders(headers) {
        const important = ['content-type', 'authorization', 'x-ratelimit-limit', 'retry-after', 'www-authenticate'];
        const filtered = {};
        let count = 0;
        
        // Always include important headers
        for (const key of important) {
            if (headers[key] && count < this.config.maxHttpHeadersCount) {
                filtered[key] = headers[key];
                count++;
            }
        }
        
        // Add other headers up to limit
        for (const [key, value] of Object.entries(headers)) {
            if (!important.includes(key.toLowerCase()) && count < this.config.maxHttpHeadersCount) {
                filtered[key] = value;
                count++;
            }
        }
        
        return filtered;
    }

    /**
     * Truncate body content intelligently
     */
    truncateBody(body) {
        if (!body) return body;
        
        if (typeof body === 'string') {
            return body.length > this.config.maxHttpBodyLength ? 
                   body.substring(0, this.config.maxHttpBodyLength) + '...[truncated]' : body;
        }
        
        if (typeof body === 'object') {
            const str = JSON.stringify(body);
            return str.length > this.config.maxHttpBodyLength ? 
                   str.substring(0, this.config.maxHttpBodyLength) + '...[truncated]' : body;
        }
        
        return body;
    }

    /**
     * Get icon for log level
     */
    getLevelIcon(level) {
        const icons = {
            'debug': '🔍',
            'info': 'ℹ️',
            'success': '✅',
            'warning': '⚠️',
            'error': '❌',
            'http': '🌐',
            'test': '🧪',
            'test-pass': '✅',
            'test-fail': '❌',
            'security': '🔒',
            'summary': '📊',
            'section': '┃'
        };
        return icons[level] || '•';
    }

    /**
     * Append log to UI container
     */
    appendToUI(message, level) {
        if (!this.container) return;
        
        const logDiv = document.createElement('div');
        logDiv.className = `log-entry log-${level}`;
        logDiv.textContent = message;
        
        this.container.appendChild(logDiv);
        this.container.scrollTop = this.container.scrollHeight;
    }

    /**
     * Log to browser console
     */
    logToConsole(entry) {
        const consoleMsg = `[Authly] ${entry.message}`;
        const consoleMeta = { ...entry.metadata, timestamp: entry.timestamp };
        
        switch(entry.level) {
            case 'error':
                console.error(consoleMsg, consoleMeta);
                break;
            case 'warning':
                console.warn(consoleMsg, consoleMeta);
                break;
            case 'debug':
                console.debug(consoleMsg, consoleMeta);
                break;
            default:
                console.log(consoleMsg, consoleMeta);
        }
    }

    /**
     * Log HTTP request/response with smart truncation
     */
    logHTTP(method, url, options = {}, response = null, responseData = null) {
        const metadata = {
            request: {
                method,
                url,
                headers: this.filterHeaders(options.headers || {}),
                body: this.truncateBody(options.body)
            }
        };
        
        if (response) {
            const responseHeaders = {};
            if (response.headers) {
                response.headers.forEach((value, key) => {
                    responseHeaders[key] = value;
                });
            }
            
            metadata.response = {
                status: response.status,
                statusText: response.statusText,
                headers: this.filterHeaders(responseHeaders),
                body: this.truncateBody(responseData)
            };
        }
        
        const level = response && response.status >= 400 ? 'error' : 'http';
        const shortUrl = url.replace(/^.*?\/api/, '/api');
        let message = `${method} ${shortUrl}`;
        
        if (response) {
            message += ` → ${response.status}`;
            if (responseData && typeof responseData === 'object' && responseData.error) {
                message += `: {"error": "${responseData.error}", "error_description": "${responseData.error_description || ''}"}`;;
            }
        }
        
        return this.log(message, level, metadata);
    }

    /**
     * Log test execution with enhanced failure details
     */
    logTest(testName, result, details = {}) {
        // Update test statistics
        this.testResults.total++;
        if (result === 'passed') {
            this.testResults.passed++;
        } else if (result === 'failed') {
            this.testResults.failed++;
            this.testResults.failures.push({
                name: testName,
                error: details.error || 'Test failed',
                expected: details.expected,
                actual: details.actual,
                endpoint: details.endpoint,
                suggestion: details.suggestion
            });
        }
        
        const metadata = {
            test: testName,
            result,
            ...details
        };
        
        const duration = details.duration ? ` (${details.duration}ms)` : '';
        let message = `${testName}${duration}`;
        
        const level = result === 'passed' ? 'test-pass' : result === 'failed' ? 'test-fail' : 'test';
        
        return this.log(message, level, metadata);
    }

    /**
     * Create section separator with visual hierarchy
     */
    section(title, level = 'info') {
        const separator = '═'.repeat(Math.min(title.length + 8, 50));
        this.log('', level);
        this.log(`╔${separator}╗`, 'section');
        this.log(`║    ${title.toUpperCase()}    ║`, 'section');
        this.log(`╚${separator}╝`, 'section');
        this.log('', level);
    }

    /**
     * Create subsection with compact format
     */
    subsection(title, level = 'info') {
        this.log('', level);
        this.log(`┌─ ${title}`, 'section');
    }

    /**
     * Log with indentation
     */
    indent(message, level = 'info', depth = 1) {
        const spaces = '  '.repeat(depth);
        return this.log(`${spaces}${message}`, level);
    }

    /**
     * Get formatted logs for clipboard
     */
    getClipboardText() {
        const header = [
            '╔══════════════════════════════════════════════════════════════╗',
            '║         Authly Compliance Tester - Execution Log             ║',
            '╚══════════════════════════════════════════════════════════════╝',
            '',
            `Session ID: ${this.sessionId}`,
            `Start Time: ${this.startTime.toISOString()}`,
            `End Time: ${new Date().toISOString()}`,
            `Total Logs: ${this.detailedLogs.length}`,
            '',
            '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
            ''
        ];
        
        return header.join('\n') + '\n' + this.detailedLogs.join('\n\n');
    }

    /**
     * Get display logs as HTML
     */
    getDisplayHTML() {
        return this.displayLogs.map(log => 
            `<div class="log-entry">${this.escapeHtml(log)}</div>`
        ).join('\n');
    }

    /**
     * Clear all logs
     */
    clear() {
        this.logs = [];
        this.displayLogs = [];
        this.detailedLogs = [];
        if (this.container) {
            this.container.innerHTML = '';
        }
        this.startTime = new Date();
        this.log('Log cleared', 'info');
    }

    /**
     * Export logs as JSON
     */
    exportJSON() {
        return JSON.stringify({
            sessionId: this.sessionId,
            startTime: this.startTime,
            endTime: new Date(),
            logs: this.logs
        }, null, 2);
    }

    /**
     * Escape HTML for safe display
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Generate comprehensive test summary following guidelines
     */
    generateTestSummary(config = {}) {
        const { total, passed, failed, failures } = this.testResults;
        const passRate = total > 0 ? ((passed / total) * 100).toFixed(1) : '0.0';
        const timestamp = new Date().toISOString();
        
        const lines = [
            '🔐 Authly Compliance Test Results',
            '═'.repeat(50),
            `Server: ${config.serverUrl || 'http://localhost:8000'}`,
            `Client ID: ${config.clientId || 'N/A'}`,
            `Time: ${timestamp}`,
            '═'.repeat(50),
            '',
            `📊 Test Summary:`,
            `• Total Tests: ${total}`,
            `• Passed: ${passed} ✅`,
            `• Failed: ${failed} ❌`,
            `• Pass Rate: ${passRate}%`,
            ''
        ];
        
        if (failures.length > 0) {
            lines.push('❌ FAILED TESTS:');
            failures.forEach((failure, index) => {
                lines.push(`${index + 1}. ${failure.name}`);
                if (failure.error) {
                    lines.push(`   Problem: ${failure.error}`);
                }
                if (failure.expected && failure.actual) {
                    lines.push(`   Expected: ${failure.expected}`);
                    lines.push(`   Actual: ${failure.actual}`);
                }
                if (failure.endpoint) {
                    lines.push(`   Endpoint: ${failure.endpoint}`);
                }
                if (failure.suggestion) {
                    lines.push(`   Fix: ${failure.suggestion}`);
                }
                lines.push('');
            });
        }
        
        if (passed > 0) {
            lines.push(`✅ PASSED: ${passed} tests`);
            lines.push('');
        }
        
        if (failed > 0) {
            lines.push('⚠️ Action Required:');
            lines.push(`Fix ${failed} failing test${failed > 1 ? 's' : ''} to achieve full compliance`);
            lines.push('');
        } else if (total > 0) {
            lines.push('🎉 Perfect Compliance Achieved!');
            lines.push('All OAuth 2.1 and OIDC requirements satisfied.');
            lines.push('');
        }
        
        lines.push('Run with --verbose for detailed HTTP logs');
        
        return lines.join('\n');
    }

    /**
     * Log rate limiting test results in compact format
     */
    logRateLimitTest(requests, results) {
        const statusCounts = {};
        let rateLimitTriggered = false;
        let triggerPoint = -1;
        
        results.forEach((result, index) => {
            const status = result.status || 'unknown';
            statusCounts[status] = (statusCounts[status] || 0) + 1;
            
            if (status === 429 && !rateLimitTriggered) {
                rateLimitTriggered = true;
                triggerPoint = index + 1;
            }
        });
        
        const statusSummary = Object.entries(statusCounts)
            .map(([status, count]) => `${count}x ${status}`)
            .join(', ');
        
        this.log(`Rate Limit Test: ${requests} requests sent`, 'test');
        this.log(`Results: ${statusSummary}`, 'info');
        
        if (rateLimitTriggered) {
            this.log(`Rate limit triggered successfully at request #${triggerPoint}`, 'success');
        } else {
            this.log('Rate limiting not detected', 'warning');
        }
    }

    /**
     * Configure logging behavior
     */
    configure(config) {
        this.config = { ...this.config, ...config };
    }

    /**
     * Reset test results
     */
    resetTestResults() {
        this.testResults = {
            total: 0,
            passed: 0,
            failed: 0,
            failures: [],
            duration: 0
        };
    }

    // Convenience methods
    debug(message, metadata = {}) { return this.log(message, 'debug', metadata); }
    info(message, metadata = {}) { return this.log(message, 'info', metadata); }
    success(message, metadata = {}) { return this.log(message, 'success', metadata); }
    warning(message, metadata = {}) { return this.log(message, 'warning', metadata); }
    error(message, metadata = {}) { return this.log(message, 'error', metadata); }
}

// Make Logger available globally
window.Logger = Logger;