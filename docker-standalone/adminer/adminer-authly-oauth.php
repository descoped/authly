<?php
/**
 * Adminer OAuth2 Authentication Plugin for Authly
 * 
 * This plugin authenticates users via Authly OAuth2 Bearer tokens
 * and provides database access based on token validation
 */

class AdminerAuthlyOAuth {
    
    private $authlyUrl;
    private $dbCredentials;
    private $requiredScopes;
    private $tokenCache = [];
    private $cacheExpiry = 300; // 5 minutes
    
    /**
     * Constructor
     * 
     * @param string $authlyUrl Base URL of Authly server
     * @param array $dbCredentials Database connection credentials
     * @param array $requiredScopes Required OAuth2 scopes
     */
    public function __construct($authlyUrl, $dbCredentials, $requiredScopes = ['database:read']) {
        $this->authlyUrl = rtrim($authlyUrl, '/');
        $this->dbCredentials = $dbCredentials;
        $this->requiredScopes = $requiredScopes;
    }
    
    /**
     * Extract Bearer token from various sources
     */
    private function getBearerToken() {
        // Check Authorization header
        $headers = null;
        
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } else if (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        
        // Extract Bearer token from header
        if (!empty($headers) && preg_match('/Bearer\s+(.*)$/i', $headers, $matches)) {
            return trim($matches[1]);
        }
        
        // Check custom header
        if (isset($_SERVER['HTTP_X_AUTH_TOKEN'])) {
            return trim($_SERVER['HTTP_X_AUTH_TOKEN']);
        }
        
        return null;
    }
    
    /**
     * Validate token with Authly's introspection endpoint
     */
    private function introspectToken($token) {
        if (empty($token)) {
            return false;
        }
        
        // Check cache first
        $cacheKey = md5($token);
        if (isset($this->tokenCache[$cacheKey])) {
            $cached = $this->tokenCache[$cacheKey];
            if ($cached['expires'] > time()) {
                return $cached['data'];
            }
            unset($this->tokenCache[$cacheKey]);
        }
        
        // Prepare introspection request
        $introspectUrl = $this->authlyUrl . '/api/v1/oauth/introspect';
        
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Content-Type: application/x-www-form-urlencoded',
                    'Accept: application/json'
                ],
                'content' => http_build_query([
                    'token' => $token,
                    'token_type_hint' => 'access_token'
                ]),
                'timeout' => 5,
                'ignore_errors' => true
            ],
            'ssl' => [
                'verify_peer' => false, // For local development
                'verify_peer_name' => false
            ]
        ]);
        
        $response = @file_get_contents($introspectUrl, false, $context);
        
        if ($response === false) {
            error_log("Authly OAuth: Failed to connect to introspection endpoint");
            return false;
        }
        
        $data = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("Authly OAuth: Invalid JSON response from introspection");
            return false;
        }
        
        // Check if token is active
        if (!isset($data['active']) || !$data['active']) {
            return false;
        }
        
        // Check expiration
        if (isset($data['exp']) && $data['exp'] < time()) {
            return false;
        }
        
        // Validate required scopes
        if (!empty($this->requiredScopes)) {
            $tokenScopes = isset($data['scope']) ? explode(' ', $data['scope']) : [];
            foreach ($this->requiredScopes as $requiredScope) {
                if (!in_array($requiredScope, $tokenScopes)) {
                    error_log("Authly OAuth: Missing required scope: " . $requiredScope);
                    return false;
                }
            }
        }
        
        // Cache the validated token
        $this->tokenCache[$cacheKey] = [
            'data' => $data,
            'expires' => time() + $this->cacheExpiry
        ];
        
        return $data;
    }
    
    /**
     * Override login method to implement OAuth2 Bearer authentication
     */
    public function login($login, $password) {
        // First try to get token from Authorization header
        $bearerToken = $this->getBearerToken();
        
        // If no bearer token in header, check if password field contains token
        if (!$bearerToken && !empty($password) && (empty($login) || $login === 'token')) {
            $bearerToken = $password;
        }
        
        if (!$bearerToken) {
            return null; // Let default auth handle it
        }
        
        // Validate the token
        $tokenInfo = $this->introspectToken($bearerToken);
        
        if ($tokenInfo === false) {
            return false; // Invalid token
        }
        
        // Store user info in session
        $_SESSION['authly_oauth_user'] = $tokenInfo;
        $_SESSION['authly_oauth_token'] = $bearerToken;
        
        return true;
    }
    
    /**
     * Override credentials to provide database connection details
     */
    public function credentials() {
        // Only provide credentials if we have a valid OAuth session
        if (!isset($_SESSION['authly_oauth_user'])) {
            return null;
        }
        
        return [
            $this->dbCredentials['server'],
            $this->dbCredentials['username'],
            $this->dbCredentials['password']
        ];
    }
    
    /**
     * Override database method to specify database name
     */
    public function database() {
        return $this->dbCredentials['database'] ?? null;
    }
    
    /**
     * Custom login form with Bearer token field
     */
    public function loginFormField($name, $heading, $value) {
        if ($name == 'username') {
            return $heading . '<input type="text" name="auth[username]" id="username" value="token" readonly style="background-color: #f0f0f0;">' .
                   '<script>document.getElementById("username").style.display = "none";</script>';
        }
        
        if ($name == 'password') {
            return '<label for="password">OAuth Bearer Token</label>' .
                   '<input type="password" name="auth[password]" id="password" value="" placeholder="Paste your Authly bearer token here" autocomplete="off">' .
                   '<div style="margin-top: 5px; font-size: 0.9em; color: #666;">' .
                   'Get token: <code>curl -X POST ' . h($this->authlyUrl) . '/api/v1/oauth/token -d "grant_type=password&username=YOUR_USER&password=YOUR_PASS"</code>' .
                   '</div>';
        }
        
        if ($name == 'db') {
            return ''; // Hide database field, it's set automatically
        }
        
        return null;
    }
    
    /**
     * Add custom name to Adminer
     */
    public function name() {
        $user = isset($_SESSION['authly_oauth_user']) ? $_SESSION['authly_oauth_user'] : null;
        if ($user && isset($user['sub'])) {
            return 'Adminer (Authly OAuth) - ' . h($user['sub']);
        }
        return 'Adminer (Authly OAuth)';
    }
    
    /**
     * Navigation message
     */
    public function navigation($missing) {
        if (isset($_SESSION['authly_oauth_user'])) {
            $user = $_SESSION['authly_oauth_user'];
            echo '<p class="logout">Logged in via Authly OAuth as: <b>' . h($user['sub'] ?? 'Unknown') . '</b></p>';
            if (isset($user['scope'])) {
                echo '<p style="font-size: 0.9em; color: #666;">Scopes: ' . h($user['scope']) . '</p>';
            }
        }
    }
}

// Main plugin initialization
function adminer_object() {
    // Include Adminer plugin interface if exists
    if (file_exists("./plugins/plugin.php")) {
        include_once "./plugins/plugin.php";
    }
    
    // Configuration from environment variables
    $authlyUrl = getenv('AUTHLY_URL') ?: 'http://authly-standalone:8000';
    
    $dbCredentials = [
        'server' => getenv('DB_SERVER') ?: 'authly-standalone',
        'username' => getenv('DB_USERNAME') ?: 'authly',
        'password' => getenv('DB_PASSWORD') ?: 'authly',
        'database' => getenv('DB_NAME') ?: 'authly'
    ];
    
    // Parse required scopes from environment
    $requiredScopes = getenv('REQUIRED_SCOPES') ? 
        explode(',', getenv('REQUIRED_SCOPES')) : 
        ['database:read', 'database:write'];
    
    $plugins = [
        new AdminerAuthlyOAuth($authlyUrl, $dbCredentials, $requiredScopes)
    ];
    
    // Include other useful plugins if available
    if (file_exists("./plugins/login-servers.php")) {
        include "./plugins/login-servers.php";
        $plugins[] = new AdminerLoginServers([
            'PostgreSQL (OAuth)' => [
                'server' => $dbCredentials['server'],
                'driver' => 'pgsql'
            ]
        ]);
    }
    
    return new AdminerPlugin($plugins);
}

// Include the original Adminer if not using plugin system
if (!class_exists('AdminerPlugin')) {
    include "./adminer.php";
}