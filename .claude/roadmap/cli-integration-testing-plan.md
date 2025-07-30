# CLI Integration Testing - Full Coverage Plan

## 🎯 **Objective**
Achieve 100% integration test coverage for the Authly CLI interface, ensuring all commands, arguments, options, and error scenarios are thoroughly tested.

## 📊 **Current State Analysis**

### ✅ **Already Covered (85% service layer)**
- Service layer functionality (ClientService, ScopeService)
- Basic command structure and help text validation
- Error handling for service methods
- Client-scope associations

### ❌ **Critical Gaps**
- **Main CLI Entry Point**: `python -m authly` commands (0% coverage)
- **Authentication Commands**: Login/logout flows (0% coverage)  
- **Real CLI Interface**: Actual command execution vs service layer (20% coverage)
- **Error Message Integration**: AdminAPIError handling (0% coverage)
- **Command Arguments**: ID/name parameters (40% coverage)

---

## 🗺️ **Implementation Roadmap**

### **Phase 1: Foundation & Infrastructure** ⏱️ *2-3 days*

#### **1.1 Test Infrastructure Setup**
- **File**: `tests/test_main_cli_integration.py`
- **Scope**: Main CLI entry point testing infrastructure
- **Tasks**:
  ```python
  # Create comprehensive CLI test framework
  class TestMainCLIIntegration:
      """Test python -m authly commands directly"""
      
      @pytest.fixture
      def cli_runner_with_env(self):
          """CLI runner with proper environment setup"""
      
      @pytest.fixture  
      def mock_server_running(self):
          """Ensure test server is running for CLI commands"""
  ```

#### **1.2 Authentication Test Framework**
- **File**: `tests/test_cli_authentication.py`
- **Scope**: Admin authentication flow testing
- **Tasks**:
  ```python
  class TestCLIAuthentication:
      """Test admin login/logout/token flows"""
      
      def test_admin_login_flow(self):
          """Test complete login process"""
      
      def test_token_persistence(self):
          """Test token storage and retrieval"""
  ```

#### **1.3 Error Handling Test Framework**
- **File**: `tests/test_cli_error_handling.py`
- **Scope**: AdminAPIError and user-friendly messages
- **Tasks**:
  ```python
  class TestCLIErrorHandling:
      """Test improved error messages and AdminAPIError integration"""
      
      def test_duplicate_resource_errors(self):
          """Test duplicate scope/client error messages"""
      
      def test_authentication_errors(self):
          """Test auth failure messages"""
  ```

### **Phase 2: Core CLI Commands** ⏱️ *3-4 days*

#### **2.1 Main CLI Entry Point**
- **Target**: `python -m authly` commands
- **Priority**: **CRITICAL** - This is the primary user interface

```python
class TestMainCLICommands:
    """Test main CLI entry point: python -m authly"""
    
    def test_default_serve_command(self):
        """Test: python -m authly (defaults to serve)"""
        
    def test_serve_command_options(self):
        """Test: python -m authly serve --host --port --workers --embedded --seed"""
        
    def test_version_command(self):
        """Test: python -m authly --version"""
        
    def test_help_command(self):
        """Test: python -m authly --help"""
```

#### **2.2 Admin Status Command**
- **Target**: `python -m authly admin status`
- **Priority**: **HIGH** - Recently fixed, needs coverage

```python
def test_admin_status_command(self):
    """Test admin status with proper statistics parsing"""
    # Verify correct OAuth client/scope counts
    # Test verbose mode
    # Test JSON output format
```

#### **2.3 Admin Client Commands**
- **Target**: `python -m authly admin client *`
- **Priority**: **HIGH** - Core functionality

```python
class TestAdminClientCommands:
    """Test python -m authly admin client commands"""
    
    def test_client_create_command(self):
        """Test: python -m authly admin client create --name --client-type --redirect-uri"""
        # Test with correct parameter names
        # Test multiple redirect URIs
        # Test with scopes
        
    def test_client_list_command(self):
        """Test: python -m authly admin client list --format"""
        # Test table and JSON output
        # Test pagination options
        
    def test_client_show_update_delete(self):
        """Test commands requiring client_id argument"""
        # Test show, update, delete with real client IDs
        # Test error handling for non-existent IDs
```

#### **2.4 Admin Scope Commands**
- **Target**: `python -m authly admin scope *`
- **Priority**: **HIGH** - Core functionality

```python
class TestAdminScopeCommands:
    """Test python -m authly admin scope commands"""
    
    def test_scope_create_command(self):
        """Test: python -m authly admin scope create --name --description"""
        # Test with correct parameter requirements
        # Test default scope creation
        
    def test_scope_list_command(self):
        """Test: python -m authly admin scope list --format"""
        # Test table and JSON output
        
    def test_scope_show_update_delete(self):
        """Test commands requiring scope_name argument"""
        # Test show, update, delete with real scope names
        # Test error handling for non-existent names
```

### **Phase 3: Authentication Integration** ⏱️ *2-3 days*

#### **3.1 Authentication Commands**
- **Priority**: **CRITICAL** - No current coverage

```python
class TestAuthenticationCommands:
    """Test all authentication-related CLI commands"""
    
    def test_admin_login_command(self):
        """Test: python -m authly admin login"""
        # Test interactive and non-interactive modes
        # Test custom API URL
        # Test scope specification
        
    def test_admin_logout_command(self):
        """Test: python -m authly admin logout"""
        # Test token cleanup
        # Test multiple logout calls
        
    def test_admin_whoami_command(self):
        """Test: python -m authly admin whoami"""
        # Test authenticated and unauthenticated states
        # Test verbose mode
        
    def test_auth_group_commands(self):
        """Test: python -m authly admin auth [login|logout|whoami|status|refresh]"""
        # Test auth subgroup commands
        # Verify aliases work correctly
        
    def test_auth_status_command(self):
        """Test: python -m authly admin auth status"""
        # Test API connection status
        # Test authentication status display
        
    def test_auth_refresh_command(self):
        """Test: python -m authly admin auth refresh"""
        # Test token refresh functionality
        # Test refresh failure scenarios
```

#### **3.2 Authentication Flow Integration**
```python
class TestAuthenticationFlows:
    """Test complete authentication workflows"""
    
    def test_login_command_workflow(self):
        """Test complete login -> command -> logout workflow"""
        # Login with CLI
        # Execute admin commands
        # Verify token usage
        # Logout and verify cleanup
        
    def test_token_persistence(self):
        """Test token storage and retrieval between CLI calls"""
        # Login and verify token file creation
        # Run commands using stored tokens
        # Test token expiration handling
```

### **Phase 4: Error Handling & Edge Cases** ⏱️ *2-3 days*

#### **4.1 AdminAPIError Integration**
- **Priority**: **HIGH** - Recently implemented, needs coverage

```python
class TestAdminAPIErrorIntegration:
    """Test AdminAPIError exception handling in CLI"""
    
    def test_duplicate_scope_error(self):
        """Test improved duplicate scope error message"""
        # Create scope, try to create again
        # Verify user-friendly error message
        # Verify no Mozilla.org references
        
    def test_duplicate_client_error(self):
        """Test improved duplicate client error message"""
        
    def test_invalid_redirect_uri_error(self):
        """Test improved redirect URI error message"""
        
    def test_authentication_errors(self):
        """Test authentication failure messages"""
        # Invalid credentials
        # Expired tokens
        # Missing permissions
        
    def test_connection_errors(self):
        """Test API connection failure messages"""
        # Server not running
        # Network issues
        # Timeout scenarios
```

#### **4.2 Parameter Validation**
```python
class TestParameterValidation:
    """Test CLI parameter validation and error messages"""
    
    def test_required_parameters(self):
        """Test missing required parameters"""
        # Missing --name for client/scope create
        # Missing --redirect-uri for client create
        
    def test_invalid_parameters(self):
        """Test invalid parameter values"""
        # Invalid client-type values
        # Invalid output formats
        # Invalid URLs
        
    def test_parameter_combinations(self):
        """Test parameter combination validation"""
        # Conflicting options
        # Dependent parameters
```

### **Phase 5: Advanced Scenarios** ⏱️ *2-3 days*

#### **5.1 End-to-End Workflows**
```python
class TestE2EWorkflows:
    """Test complete real-world CLI workflows"""
    
    def test_complete_oauth_setup_workflow(self):
        """Test setting up OAuth from scratch using CLI"""
        # Start server
        # Login as admin
        # Create scopes
        # Create client
        # Test client functionality
        
    def test_client_management_workflow(self):
        """Test complete client lifecycle via CLI"""
        # Create client
        # Update client details
        # Regenerate secret
        # Test client operations
        # Delete client
        
    def test_scope_management_workflow(self):
        """Test complete scope lifecycle via CLI"""
        # Create scope
        # Update scope details
        # Create client with scope
        # Test scope functionality
        # Delete scope
```

#### **5.2 Output Format Testing**
```python
class TestOutputFormats:
    """Test all CLI output formats and modes"""
    
    def test_table_output_format(self):
        """Test table output formatting"""
        # Verify table structure
        # Test column alignment
        # Test data truncation
        
    def test_json_output_format(self):
        """Test JSON output formatting"""
        # Verify valid JSON structure
        # Test data completeness
        # Test parsing compatibility
        
    def test_verbose_modes(self):
        """Test verbose output options"""
        # Test --verbose flags
        # Test debug information
        # Test error details
```

### **Phase 6: Integration & Performance** ⏱️ *1-2 days*

#### **6.1 Cross-Command Integration**
```python
class TestCrossCommandIntegration:
    """Test interactions between different CLI commands"""
    
    def test_command_state_persistence(self):
        """Test that CLI commands properly maintain state"""
        # Token persistence across commands
        # Configuration consistency
        
    def test_concurrent_cli_usage(self):
        """Test multiple CLI instances"""
        # Multiple logins
        # Concurrent operations
        # Token sharing/conflicts
```

#### **6.2 Performance & Resource Testing**
```python
class TestCLIPerformance:
    """Test CLI performance and resource usage"""
    
    def test_command_execution_time(self):
        """Test CLI command performance"""
        # Login time
        # Command execution time
        # Bulk operations
        
    def test_resource_cleanup(self):
        """Test proper resource cleanup"""
        # Database connections
        # Token cleanup
        # Temporary files
```

---

## 📁 **File Organization Plan**

### **New Test Files to Create**
```
tests/integration/cli/
├── __init__.py
├── test_main_cli_integration.py          # Phase 1 & 2
├── test_cli_authentication.py            # Phase 3
├── test_cli_error_handling.py            # Phase 4
├── test_cli_workflows.py                 # Phase 5
├── fixtures/
│   ├── __init__.py
│   ├── cli_fixtures.py                   # Reusable CLI test fixtures
│   └── auth_fixtures.py                  # Authentication test fixtures
└── helpers/
    ├── __init__.py
    ├── cli_test_helpers.py                # CLI testing utilities
    └── assertion_helpers.py               # Custom assertion helpers
```

### **Existing Files to Update**
```
tests/test_admin_cli.py                    # Fix parameter names and add missing coverage
tests/conftest.py                          # Add CLI-specific fixtures
```

---

## 🔧 **Technical Implementation Details**

### **Test Infrastructure Requirements**

#### **1. CLI Test Runner Setup**
```python
@pytest.fixture
def cli_runner_with_server():
    """CLI runner that ensures test server is running"""
    # Start embedded test server if not running
    # Configure environment variables
    # Return CliRunner with proper setup
    
@pytest.fixture  
def authenticated_cli_runner():
    """CLI runner with admin authentication pre-configured"""
    # Setup admin login
    # Configure token storage
    # Return ready-to-use runner
```

#### **2. Environment Configuration**
```python
@pytest.fixture
def cli_test_environment():
    """Setup isolated CLI test environment"""
    # Set AUTHLY_API_URL
    # Setup temporary token storage
    # Configure test database
    # Clean environment variables
```

#### **3. Assertion Helpers**
```python
def assert_cli_success(result, expected_output=None):
    """Assert CLI command succeeded with expected output"""
    
def assert_cli_error(result, expected_error_message):
    """Assert CLI command failed with expected error"""
    
def assert_json_output(result, expected_structure):
    """Assert CLI JSON output matches expected structure"""
```

### **Coverage Measurement**
```python
# Add to pytest configuration
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = [
    "--cov=src/authly",
    "--cov-report=html:htmlcov/cli",
    "--cov-report=term-missing",
    "--cov-branch",
]

# CLI-specific coverage tracking
markers = [
    "cli: marks tests as CLI integration tests",
    "auth: marks tests as authentication tests", 
    "error_handling: marks tests as error handling tests",
]
```

---

## 📈 **Success Metrics**

### **Coverage Targets**
- **Main CLI Commands**: 100% coverage
- **Authentication Flow**: 100% coverage  
- **Error Handling**: 95% coverage
- **Command Arguments**: 100% coverage
- **Output Formats**: 100% coverage

### **Quality Gates**
- ✅ All CLI commands tested with real invocation
- ✅ All parameter combinations validated
- ✅ All error scenarios covered
- ✅ All output formats verified
- ✅ Authentication flows fully tested
- ✅ AdminAPIError integration verified

### **Performance Benchmarks**
- CLI command execution time < 2 seconds
- Authentication flow < 5 seconds
- No memory leaks in CLI operations
- Proper resource cleanup verified

---

## 🎯 **Execution Timeline**

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| **Phase 1** | 2-3 days | Test infrastructure, frameworks |
| **Phase 2** | 3-4 days | Core CLI command coverage |
| **Phase 3** | 2-3 days | Authentication integration |
| **Phase 4** | 2-3 days | Error handling & validation |
| **Phase 5** | 2-3 days | Advanced scenarios & workflows |
| **Phase 6** | 1-2 days | Integration & performance |
| **Total** | **12-18 days** | **100% CLI coverage** |

---

## 🚀 **Implementation Priority**

### **Critical (Start Immediately)**
1. **Main CLI Entry Point Testing** - Users interact with `python -m authly`
2. **Authentication Command Testing** - Core security functionality
3. **AdminAPIError Integration** - Recently implemented, needs validation

### **High Priority (Week 1)**
4. **Core Admin Commands** - client/scope management
5. **Parameter Validation** - Prevent user errors
6. **Status Command Testing** - Recently fixed functionality

### **Medium Priority (Week 2)**
7. **Output Format Testing** - User experience
8. **Error Scenario Coverage** - Edge cases
9. **E2E Workflow Testing** - Real-world usage

### **Low Priority (Final Phase)**
10. **Performance Testing** - Optimization
11. **Concurrent Usage Testing** - Advanced scenarios
12. **Documentation Updates** - Test documentation

---

## 📋 **Pre-Implementation Checklist**

- [ ] Review current test structure and identify conflicts
- [ ] Ensure test database isolation for CLI tests
- [ ] Setup CI/CD pipeline updates for CLI test execution
- [ ] Plan test data management strategy
- [ ] Configure test environment variables
- [ ] Setup test server startup/shutdown procedures
- [ ] Review CLI command documentation for test scenarios
- [ ] Identify test dependencies and fixtures needed

---

**This plan ensures comprehensive CLI integration test coverage while maintaining maintainable, reliable test suites that accurately reflect real user interactions with the Authly CLI.**