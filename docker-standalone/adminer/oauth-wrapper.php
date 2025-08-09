<?php
// OAuth wrapper for Adminer - validates tokens before loading Adminer

// Start output buffering to prevent header issues
ob_start();

session_start();

// Pre-populate form fields if not already set
if (!isset($_GET['pgsql'])) {
    $_GET['pgsql'] = getenv('DB_SERVER') ?: 'authly-standalone';
}
if (!isset($_GET['username'])) {
    $_GET['username'] = 'admin';  // Show 'admin' in the form (will be replaced with token)
}
if (!isset($_GET['db'])) {
    $_GET['db'] = getenv('DB_NAME') ?: 'authly';
}
if (!isset($_GET['ns'])) {
    $_GET['ns'] = 'public';
}

// Auto-generate token for development (ONLY for non-production)
function getDevToken() {
    $authlyUrl = getenv('AUTHLY_URL') ?: 'http://authly-standalone:8000';
    $adminPassword = getenv('AUTHLY_ADMIN_PASSWORD') ?: 'ci_admin_test_password';
    
    $ch = curl_init($authlyUrl . '/api/v1/oauth/token');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'grant_type' => 'password',
        'username' => 'admin',
        'password' => $adminPassword,
        'scope' => 'database:read database:write'
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200 && $response) {
        $data = json_decode($response, true);
        return $data['access_token'] ?? null;
    }
    
    return null;
}

// Store the dev token for pre-population
$devToken = null;
if (!isset($_SESSION['oauth_validated']) && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Only get token for login page
    $devToken = getDevToken();
    error_log("DevToken generated: " . ($devToken ? substr($devToken, 0, 20) . '...' : 'null'));
    error_log("Request from: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

// Check if we're processing a login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['auth'])) {
    $password = $_POST['auth']['password'] ?? '';
    
    // Check if password looks like a JWT token
    if (preg_match('/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/', $password)) {
        // Validate token with Authly
        $authlyUrl = getenv('AUTHLY_URL') ?: 'http://authly-standalone:8000';
        $introspectUrl = $authlyUrl . '/api/v1/oauth/introspect';
        
        $ch = curl_init($introspectUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'token' => $password,
            'token_type_hint' => 'access_token'
        ]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 && $response) {
            $data = json_decode($response, true);
            
            // Check if token is active and has required scopes
            if (isset($data['active']) && $data['active']) {
                $scopes = isset($data['scope']) ? explode(' ', $data['scope']) : [];
                if (in_array('database:read', $scopes) && in_array('database:write', $scopes)) {
                    // Token is valid - store in session and replace password with DB password
                    $_SESSION['oauth_validated'] = true;
                    $_SESSION['oauth_user'] = $data['sub'] ?? 'unknown';
                    $_SESSION['oauth_scopes'] = $data['scope'] ?? '';
                    
                    // Replace ALL auth fields with the actual database credentials
                    $_POST['auth']['password'] = getenv('DB_PASSWORD') ?: 'authly';
                    $_POST['auth']['username'] = getenv('DB_USERNAME') ?: 'authly';
                    $_POST['auth']['server'] = getenv('DB_SERVER') ?: 'authly-standalone';
                    $_POST['auth']['db'] = getenv('DB_NAME') ?: 'authly';
                    $_POST['auth']['driver'] = 'pgsql';
                }
            }
        }
    } else {
        // Not a valid OAuth token - show error and prevent login
        $_SESSION['oauth_error'] = 'Invalid OAuth token. Please provide a valid bearer token.';
        
        // Prevent database login by setting invalid credentials
        $_POST['auth']['username'] = 'oauth_token_required';
        $_POST['auth']['password'] = 'invalid';
        $_POST['auth']['db'] = 'authly';
        
        // Since we're buffering output, we can safely redirect
        ob_end_clean(); // Clear any output
        header('Location: ?pgsql=' . (getenv('DB_SERVER') ?: 'authly-standalone') . '&username=admin&db=authly&ns=public&oauth_error=1');
        exit;
    }
}

// Store banner HTML to inject later
$banner_html = '';

// Check for OAuth error
if (isset($_GET['oauth_error']) || isset($_SESSION['oauth_error'])) {
    // Show error banner
    $error_msg = $_SESSION['oauth_error'] ?? 'OAuth authentication required. Please provide a valid bearer token.';
    unset($_SESSION['oauth_error']); // Clear error after displaying
    
    $banner_html = '<div style="background: #f44336; color: white; padding: 15px; margin: 0;">';
    $banner_html .= '<strong>⚠️ Authentication Error</strong><br>';
    $banner_html .= htmlspecialchars($error_msg) . '<br>';
    $banner_html .= '<small>Get a valid token: <code style="background: rgba(0,0,0,0.2); padding: 2px 5px;">curl -X POST http://localhost:8000/api/v1/oauth/token -d "grant_type=password&username=admin&password=YOUR_PASSWORD&scope=database:read database:write"</code></small>';
    $banner_html .= '</div>';
} else if (isset($_SESSION['oauth_validated']) && $_SESSION['oauth_validated']) {
    // Authenticated - show success banner that auto-hides
    $banner_html = '<div id="oauth-success-banner" style="background: #4CAF50; color: white; padding: 10px; margin: 0; transition: opacity 0.5s ease-in-out;">';
    $banner_html .= 'Authenticated via Authly OAuth as: <strong>' . htmlspecialchars($_SESSION['oauth_user']) . '</strong>';
    $banner_html .= ' | Scopes: ' . htmlspecialchars($_SESSION['oauth_scopes']);
    $banner_html .= '</div>';
    $banner_html .= '<script>
    setTimeout(function() {
        var banner = document.getElementById("oauth-success-banner");
        if (banner) {
            banner.style.opacity = "0";
            setTimeout(function() {
                banner.style.display = "none";
            }, 500);
        }
    }, 3000);
    </script>';
} else if (!isset($_POST['auth']) && $_SERVER['REQUEST_METHOD'] !== 'POST') {
    // Login page - show instructions
    $banner_html = '<div style="background: #2196F3; color: white; padding: 15px; margin: 0;">';
    $banner_html .= '<strong>🔐 Authly OAuth Authentication Required</strong><br>';
    $banner_html .= 'Enter your OAuth bearer token in the password field (not a regular password).<br>';
    $banner_html .= '<small>Get token: <code style="background: rgba(0,0,0,0.2); padding: 2px 5px;">curl -X POST http://localhost:8000/api/v1/oauth/token -d "grant_type=password&username=admin&password=YOUR_PASSWORD&scope=database:read database:write"</code></small>';
    $banner_html .= '</div>';
}

// Load the original Adminer
if (!file_exists('./adminer.php')) {
    error_log("ERROR: adminer.php not found at " . getcwd());
    die("Adminer not found. Please ensure adminer.php is in the same directory.");
}

// Register a shutdown function to inject our content
register_shutdown_function(function() use ($devToken, $banner_html) {
    $output = ob_get_contents();
    ob_end_clean();
    
    error_log("Shutdown function: Output captured, length: " . strlen($output));
    error_log("Shutdown function: DevToken status: " . ($devToken ? "EXISTS" : "NULL"));
    
    // Inject banner inside content div (right panel)
    if ($banner_html && strpos($output, '<div id=\'content\'>') !== false) {
        // Extract nonce if present for CSP
        $nonce = '';
        if (preg_match('/<script[^>]*nonce="([^"]+)"/', $output, $matches)) {
            $nonce = ' nonce="' . $matches[1] . '"';
        }
        
        // Update script tags in banner to include nonce
        $banner_html = str_replace('<script>', '<script' . $nonce . '>', $banner_html);
        
        // Style the banner to fit nicely in the content area
        $banner_html = str_replace(
            'style="background: #4CAF50; color: white; padding: 10px; margin: 0;',
            'style="background: #4CAF50; color: white; padding: 10px; margin: 0 0 10px 0; border-radius: 4px;',
            $banner_html
        );
        
        // Inject right after the opening of content div
        $output = str_replace('<div id=\'content\'>', '<div id=\'content\'>' . $banner_html, $output);
    }
    
    // Pre-populate password field with dev token if available
    if ($devToken) {
        error_log("Shutdown function: Attempting to inject token into HTML");
        
        // Direct value attribute injection
        $count = 0;
        $output = preg_replace(
            '/<input\s+type="password"\s+name="auth\[password\]"[^>]*>/i',
            '<input type="password" name="auth[password]" value="' . htmlspecialchars($devToken) . '" autocomplete="current-password" style="background-color:#e8f5e9;">',
            $output,
            -1,
            $count
        );
        error_log("Shutdown function: Replaced $count password fields");
        
        // Add JavaScript as backup
        $jsCode = '
        <script>
        window.addEventListener("load", function() {
            var passwordField = document.querySelector(\'input[name="auth[password]"]\');
            if (passwordField && !passwordField.value) {
                passwordField.value = ' . json_encode($devToken) . ';
                passwordField.style.backgroundColor = "#e8f5e9";
            }
            
            // Add a note near the password field
            var submitBtn = document.querySelector(\'input[type="submit"]\');
            if (submitBtn && !document.getElementById("token-note")) {
                var note = document.createElement("div");
                note.id = "token-note";
                note.innerHTML = "<strong style=\'color:#4CAF50;\'>✓ OAuth token auto-filled - just click Login!</strong>";
                submitBtn.parentNode.insertBefore(note, submitBtn);
            }
        });
        </script>';
        
        // Inject the JavaScript before the closing body tag
        if (strpos($output, '</body>') !== false) {
            $output = str_replace('</body>', $jsCode . '</body>', $output);
        } else {
            // If no body tag, append at the end
            $output .= $jsCode;
        }
        
        // Update the password label
        $output = str_replace(
            '<tr><th>Password<td>',
            '<tr><th>Password<br><small style="font-weight:normal;color:#4CAF50">(OAuth Token Auto-filled)</small><td>',
            $output
        );
    }
    
    echo $output;
});

include './adminer.php';

// This code will only run if Adminer doesn't call exit()
error_log("After include - this may not execute if Adminer calls exit()");