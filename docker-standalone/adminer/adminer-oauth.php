<?php
// Simplified Adminer OAuth authentication for Authly

function adminer_object() {
    
    class AdminerAuthly extends Adminer {
        private $authlyUrl;
        private $dbServer;
        private $dbUser;
        private $dbPass;
        private $dbName;
        
        function __construct() {
            $this->authlyUrl = getenv('AUTHLY_URL') ?: 'http://authly-standalone:8000';
            $this->dbServer = getenv('DB_SERVER') ?: 'authly-standalone';
            $this->dbUser = getenv('DB_USERNAME') ?: 'authly';
            $this->dbPass = getenv('DB_PASSWORD') ?: 'authly';
            $this->dbName = getenv('DB_NAME') ?: 'authly';
        }
        
        function name() {
            return 'Adminer (Authly OAuth)';
        }
        
        function credentials() {
            return array($this->dbServer, $this->dbUser, $this->dbPass);
        }
        
        function database() {
            return $this->dbName;
        }
        
        function login($login, $password) {
            // If password looks like a JWT token, validate it
            if (preg_match('/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/', $password)) {
                // Validate token with Authly
                $validated = $this->validateToken($password);
                if ($validated) {
                    $_SESSION['oauth_user'] = $validated;
                    return true;
                }
                return false;
            }
            
            // Fall back to regular auth if not a token
            return parent::login($login, $password);
        }
        
        private function validateToken($token) {
            $introspectUrl = $this->authlyUrl . '/api/v1/oauth/introspect';
            
            $ch = curl_init($introspectUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
                'token' => $token,
                'token_type_hint' => 'access_token'
            ]));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode !== 200 || !$response) {
                return false;
            }
            
            $data = json_decode($response, true);
            
            // Check if token is active
            if (!isset($data['active']) || !$data['active']) {
                return false;
            }
            
            // Check for required scopes
            $scopes = isset($data['scope']) ? explode(' ', $data['scope']) : [];
            if (!in_array('database:read', $scopes) || !in_array('database:write', $scopes)) {
                return false;
            }
            
            return $data;
        }
        
        function loginForm() {
            ?>
            <table cellspacing="0">
                <tr>
                    <th><?php echo lang('Username'); ?></th>
                    <td><input type="text" name="auth[username]" value="token" style="display:none;">OAuth Token</td>
                </tr>
                <tr>
                    <th><?php echo lang('Password'); ?></th>
                    <td><input type="password" name="auth[password]" id="password" placeholder="Paste your Authly bearer token"></td>
                </tr>
            </table>
            <p>
                <small>Get token: <code>curl -X POST <?php echo h($this->authlyUrl); ?>/api/v1/oauth/token -d "grant_type=password&username=USER&password=PASS&scope=database:read database:write"</code></small>
            </p>
            <p><input type="submit" value="<?php echo lang('Login'); ?>"></p>
            <?php
            return true;
        }
    }
    
    return new AdminerAuthly();
}

include "./adminer.php";