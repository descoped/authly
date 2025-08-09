<?php
// Adminer with Authly OAuth authentication

// Define the adminer_object function before including adminer.php
function adminer_object() {
    // Include the original Adminer class first
    class Adminer {
        // Placeholder - will be overridden by the real Adminer class
    }
    
    // Include the plugin base
    include_once "./plugins/plugin.php";
    
    // Include our OAuth plugin
    include_once "./adminer-authly-oauth.php";
    
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
    
    // Check if AdminerPlugin class exists
    if (class_exists('AdminerPlugin')) {
        return new AdminerPlugin($plugins);
    } else {
        // Fallback - return a simple Adminer extension
        return new AdminerAuthlyOAuth($authlyUrl, $dbCredentials, $requiredScopes);
    }
}

// Include the original Adminer
include "./adminer.php";