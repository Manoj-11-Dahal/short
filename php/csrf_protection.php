<?php
/**
 * CSRF Protection Implementation
 * 
 * This file provides functions for generating and validating CSRF tokens
 * to protect against Cross-Site Request Forgery attacks.
 */

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Generate a new CSRF token
 * 
 * @return string The generated token
 */
function generateCsrfToken() {
    // Generate a cryptographically secure random token
    $token = bin2hex(random_bytes(32));
    
    // Store token in session with expiration time (1 hour)
    $_SESSION['csrf_token'] = [
        'token' => $token,
        'expires' => time() + 3600 // 1 hour expiration
    ];
    
    // Set token in cookie for JavaScript access with secure attributes
    setcookie(
        'csrf_token',
        $token,
        [
            'expires' => time() + 3600,
            'path' => '/',
            'secure' => true,     // Only send over HTTPS
            'httponly' => false,  // Allow JavaScript access
            'samesite' => 'Strict' // Prevent CSRF
        ]
    );
    
    return $token;
}

/**
 * Get the current CSRF token or generate a new one if needed
 * 
 * @return string The current CSRF token
 */
function getCsrfToken() {
    // Check if token exists and is not expired
    if (isset($_SESSION['csrf_token']) && 
        isset($_SESSION['csrf_token']['token']) && 
        isset($_SESSION['csrf_token']['expires']) && 
        $_SESSION['csrf_token']['expires'] > time()) {
        
        return $_SESSION['csrf_token']['token'];
    }
    
    // Generate new token if not exists or expired
    return generateCsrfToken();
}

/**
 * Validate CSRF token from request
 * 
 * @param string $token Token to validate (if null, will try to get from request)
 * @return bool True if valid, false otherwise
 */
function validateCsrfToken($token = null) {
    // If no token provided, try to get from request
    if ($token === null) {
        // Check header
        $headers = getallheaders();
        if (isset($headers['X-CSRF-Token'])) {
            $token = $headers['X-CSRF-Token'];
        }
        // Check POST data
        elseif (isset($_POST['csrf_token'])) {
            $token = $_POST['csrf_token'];
        }
        // Check GET data
        elseif (isset($_GET['csrf_token'])) {
            $token = $_GET['csrf_token'];
        }
    }
    
    // If still no token, validation fails
    if ($token === null) {
        return false;
    }
    
    // Check if token exists and is not expired
    if (!isset($_SESSION['csrf_token']) || 
        !isset($_SESSION['csrf_token']['token']) || 
        !isset($_SESSION['csrf_token']['expires'])) {
        return false;
    }
    
    $storedToken = $_SESSION['csrf_token']['token'];
    $expires = $_SESSION['csrf_token']['expires'];
    
    // Check if token is expired
    if (time() > $expires) {
        return false;
    }
    
    // Validate token using constant-time comparison to prevent timing attacks
    return hash_equals($storedToken, $token);
}

/**
 * Add CSRF token to a form
 * 
 * @return string HTML input field with CSRF token
 */
function csrfTokenField() {
    $token = getCsrfToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

/**
 * Enforce CSRF protection for non-GET requests
 * 
 * @param array $excludedPaths Array of paths to exclude from CSRF protection
 */
function enforceCsrfProtection($excludedPaths = []) {
    // Skip for GET and OPTIONS requests
    if ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        return;
    }
    
    // Skip for excluded paths
    $currentPath = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    foreach ($excludedPaths as $path) {
        if (strpos($currentPath, $path) === 0) {
            return;
        }
    }
    
    // Validate CSRF token
    if (!validateCsrfToken()) {
        // Determine response type based on request
        $isApiRequest = (strpos($currentPath, '/api/') !== false) || 
                       (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);
        
        if ($isApiRequest) {
            // API request - return JSON error
            header('Content-Type: application/json');
            http_response_code(403);
            echo json_encode(['error' => 'CSRF validation failed']);
        } else {
            // Regular request - return HTML error
            http_response_code(403);
            echo '<h1>403 Forbidden</h1>';
            echo '<p>CSRF validation failed. Please go back and try again.</p>';
        }
        exit;
    }
}

/**
 * Get JavaScript code for adding CSRF token to AJAX requests
 * 
 * @return string JavaScript code
 */
function getCsrfJavaScript() {
    $token = getCsrfToken();
    return <<<EOT
<script>
    // Add CSRF token to all AJAX requests
    (function() {
        const token = "$token";
        
        // Add token to XMLHttpRequest
        const originalXhrOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function() {
            const result = originalXhrOpen.apply(this, arguments);
            const method = arguments[0].toUpperCase();
            
            if (method !== 'GET' && method !== 'HEAD') {
                this.setRequestHeader('X-CSRF-Token', token);
            }
            
            return result;
        };
        
        // Add token to fetch requests
        const originalFetch = window.fetch;
        window.fetch = function(url, options) {
            options = options || {};
            
            if (options.method && options.method.toUpperCase() !== 'GET' && options.method.toUpperCase() !== 'HEAD') {
                options.headers = options.headers || {};
                
                // Convert Headers object to plain object if needed
                if (options.headers instanceof Headers) {
                    const plainHeaders = {};
                    for (const [key, value] of options.headers.entries()) {
                        plainHeaders[key] = value;
                    }
                    options.headers = plainHeaders;
                }
                
                options.headers['X-CSRF-Token'] = token;
            }
            
            return originalFetch.call(this, url, options);
        };
    })();
</script>
EOT;
}
?>