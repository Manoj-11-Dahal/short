<?php
/**
 * Security Implementation File
 * 
 * This file contains comprehensive security implementations for the portfolio website
 * including input validation, CSRF protection, rate limiting, and secure error handling.
 */

// Security configuration
$securityConfig = [
    // CSRF Protection
    'csrf' => [
        'tokenLifetime' => 3600, // 1 hour
        'cookieName' => 'csrf_token',
        'headerName' => 'X-CSRF-Token',
        'formFieldName' => 'csrf_token'
    ],
    
    // Rate Limiting
    'rateLimit' => [
        'enabled' => true,
        'maxRequests' => 60, // requests per minute
        'windowSize' => 60, // seconds
        'ipHeaderName' => 'X-Forwarded-For' // for when behind proxy
    ],
    
    // Password Policy
    'passwordPolicy' => [
        'minLength' => 12,
        'requireUppercase' => true,
        'requireLowercase' => true,
        'requireNumbers' => true,
        'requireSpecialChars' => true,
        'maxAge' => 90 // days
    ],
    
    // Error Handling
    'errorHandling' => [
        'displayErrors' => false, // Set to false in production
        'logErrors' => true,
        'errorLogFile' => __DIR__ . '/../logs/error.log'
    ],
    
    // Security Headers
    'securityHeaders' => [
        'Content-Security-Policy' => "default-src 'self'; script-src 'self' https://cdn.auth0.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://*.auth0.com;",
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        'Referrer-Policy' => 'strict-origin-when-cross-origin'
    ]
];

// Create logs directory if it doesn't exist
if (!file_exists(__DIR__ . '/../logs')) {
    mkdir(__DIR__ . '/../logs', 0755, true);
}

/**
 * Input Validation and Sanitization
 */
class InputValidator {
    /**
     * Sanitize input string
     * @param string $input Input to sanitize
     * @return string Sanitized input
     */
    public static function sanitizeString($input) {
        if (is_string($input)) {
            return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
        }
        return '';
    }
    
    /**
     * Validate email address
     * @param string $email Email to validate
     * @return bool True if valid, false otherwise
     */
    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    /**
     * Validate integer
     * @param mixed $input Input to validate
     * @param int $min Minimum value (optional)
     * @param int $max Maximum value (optional)
     * @return bool True if valid, false otherwise
     */
    public static function validateInt($input, $min = null, $max = null) {
        $options = [];
        if ($min !== null) $options['min_range'] = $min;
        if ($max !== null) $options['max_range'] = $max;
        
        return filter_var($input, FILTER_VALIDATE_INT, ['options' => $options]) !== false;
    }
    
    /**
     * Validate URL
     * @param string $url URL to validate
     * @return bool True if valid, false otherwise
     */
    public static function validateUrl($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }
    
    /**
     * Validate file upload
     * @param array $file File from $_FILES
     * @param array $allowedTypes Allowed MIME types
     * @param int $maxSize Maximum file size in bytes
     * @return array Result with status and message
     */
    public static function validateFile($file, $allowedTypes, $maxSize) {
        $result = ['valid' => false, 'message' => ''];
        
        // Check if file was uploaded properly
        if (!isset($file['error']) || is_array($file['error'])) {
            $result['message'] = 'Invalid file parameters';
            return $result;
        }
        
        // Check for upload errors
        switch ($file['error']) {
            case UPLOAD_ERR_OK:
                break;
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $result['message'] = 'File is too large';
                return $result;
            case UPLOAD_ERR_PARTIAL:
                $result['message'] = 'File was only partially uploaded';
                return $result;
            case UPLOAD_ERR_NO_FILE:
                $result['message'] = 'No file was uploaded';
                return $result;
            default:
                $result['message'] = 'Unknown upload error';
                return $result;
        }
        
        // Check file size
        if ($file['size'] > $maxSize) {
            $result['message'] = 'File is too large';
            return $result;
        }
        
        // Check MIME type
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($file['tmp_name']);
        
        if (!in_array($mimeType, $allowedTypes)) {
            $result['message'] = 'File type not allowed';
            return $result;
        }
        
        $result['valid'] = true;
        return $result;
    }
}

/**
 * CSRF Protection
 */
class CSRFProtection {
    private $config;
    
    public function __construct($config) {
        $this->config = $config;
    }
    
    /**
     * Generate a new CSRF token
     * @return string The generated token
     */
    public function generateToken() {
        $token = bin2hex(random_bytes(32));
        
        // Store token in session
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $_SESSION['csrf_token'] = [
            'token' => $token,
            'expires' => time() + $this->config['tokenLifetime']
        ];
        
        // Set token in cookie for JavaScript access
        setcookie(
            $this->config['cookieName'],
            $token,
            time() + $this->config['tokenLifetime'],
            '/',
            '',  // domain
            true, // secure
            true  // httponly
        );
        
        return $token;
    }
    
    /**
     * Validate CSRF token
     * @param string $token Token to validate
     * @return bool True if valid, false otherwise
     */
    public function validateToken($token) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
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
        
        // Validate token
        return hash_equals($storedToken, $token);
    }
    
    /**
     * Get CSRF token from request
     * @return string|null Token or null if not found
     */
    public function getTokenFromRequest() {
        // Check header
        $headers = getallheaders();
        if (isset($headers[$this->config['headerName']])) {
            return $headers[$this->config['headerName']];
        }
        
        // Check POST data
        if (isset($_POST[$this->config['formFieldName']])) {
            return $_POST[$this->config['formFieldName']];
        }
        
        // Check GET data
        if (isset($_GET[$this->config['formFieldName']])) {
            return $_GET[$this->config['formFieldName']];
        }
        
        return null;
    }
    
    /**
     * Protect against CSRF
     * @param array $excludedRoutes Routes to exclude from CSRF protection
     * @return bool True if request is valid, false otherwise
     */
    public function protectAgainstCSRF($excludedRoutes = []) {
        // Skip for excluded routes
        $currentRoute = $_SERVER['REQUEST_URI'];
        foreach ($excludedRoutes as $route) {
            if (strpos($currentRoute, $route) === 0) {
                return true;
            }
        }
        
        // Skip for GET requests
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            return true;
        }
        
        // Validate token
        $token = $this->getTokenFromRequest();
        if ($token === null) {
            return false;
        }
        
        return $this->validateToken($token);
    }
}

/**
 * Rate Limiting
 */
class RateLimiter {
    private $config;
    private $conn;
    
    public function __construct($config, $conn) {
        $this->config = $config;
        $this->conn = $conn;
    }
    
    /**
     * Get client IP address
     * @return string IP address
     */
    private function getClientIP() {
        if (!empty($_SERVER[$this->config['ipHeaderName']])) {
            return $_SERVER[$this->config['ipHeaderName']];
        }
        
        return $_SERVER['REMOTE_ADDR'];
    }
    
    /**
     * Check if request is rate limited
     * @param string $endpoint Endpoint being accessed (optional)
     * @return bool True if allowed, false if limited
     */
    public function isAllowed($endpoint = '') {
        if (!$this->config['enabled']) {
            return true;
        }
        
        $ip = $this->getClientIP();
        $now = time();
        $windowStart = $now - $this->config['windowSize'];
        
        try {
            // Create rate_limits table if it doesn't exist
            $this->conn->exec("CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                INDEX idx_ip_endpoint (ip, endpoint)
            )");
            
            // Clean up old entries
            $stmt = $this->conn->prepare("DELETE FROM rate_limits WHERE timestamp < :windowStart");
            $stmt->bindParam(':windowStart', $windowStart, PDO::PARAM_INT);
            $stmt->execute();
            
            // Count requests in current window
            $stmt = $this->conn->prepare("SELECT COUNT(*) FROM rate_limits WHERE ip = :ip AND endpoint = :endpoint AND timestamp >= :windowStart");
            $stmt->bindParam(':ip', $ip, PDO::PARAM_STR);
            $stmt->bindParam(':endpoint', $endpoint, PDO::PARAM_STR);
            $stmt->bindParam(':windowStart', $windowStart, PDO::PARAM_INT);
            $stmt->execute();
            
            $count = $stmt->fetchColumn();
            
            // Check if limit exceeded
            if ($count >= $this->config['maxRequests']) {
                return false;
            }
            
            // Record this request
            $stmt = $this->conn->prepare("INSERT INTO rate_limits (ip, endpoint, timestamp) VALUES (:ip, :endpoint, :timestamp)");
            $stmt->bindParam(':ip', $ip, PDO::PARAM_STR);
            $stmt->bindParam(':endpoint', $endpoint, PDO::PARAM_STR);
            $stmt->bindParam(':timestamp', $now, PDO::PARAM_INT);
            $stmt->execute();
            
            return true;
        } catch (PDOException $e) {
            // Log error but don't block request if rate limiting fails
            error_log("Rate limiting error: " . $e->getMessage());
            return true;
        }
    }
    
    /**
     * Apply rate limiting headers
     * @param bool $isLimited Whether request is limited
     */
    public function applyHeaders($isLimited) {
        header('X-RateLimit-Limit: ' . $this->config['maxRequests']);
        
        if ($isLimited) {
            header('X-RateLimit-Remaining: 0');
            header('Retry-After: ' . $this->config['windowSize']);
            http_response_code(429); // Too Many Requests
        }
    }
}

/**
 * Secure Error Handler
 */
class SecureErrorHandler {
    private $config;
    
    public function __construct($config) {
        $this->config = $config;
        
        // Set error handling configuration
        ini_set('display_errors', $this->config['displayErrors'] ? '1' : '0');
        ini_set('log_errors', $this->config['logErrors'] ? '1' : '0');
        
        if ($this->config['logErrors'] && !empty($this->config['errorLogFile'])) {
            ini_set('error_log', $this->config['errorLogFile']);
        }
        
        // Register error handler
        set_error_handler([$this, 'handleError']);
        set_exception_handler([$this, 'handleException']);
        register_shutdown_function([$this, 'handleFatalError']);
    }
    
    /**
     * Handle PHP errors
     */
    public function handleError($errno, $errstr, $errfile, $errline) {
        if (!(error_reporting() & $errno)) {
            // This error code is not included in error_reporting
            return false;
        }
        
        $this->logError($errno, $errstr, $errfile, $errline);
        
        if ($this->config['displayErrors']) {
            $this->displayError($errno, $errstr, $errfile, $errline);
        } else {
            $this->displayGenericError();
        }
        
        // Don't execute PHP internal error handler
        return true;
    }
    
    /**
     * Handle exceptions
     */
    public function handleException($exception) {
        $this->logError(
            E_ERROR,
            $exception->getMessage(),
            $exception->getFile(),
            $exception->getLine(),
            $exception->getTraceAsString()
        );
        
        if ($this->config['displayErrors']) {
            $this->displayError(
                E_ERROR,
                $exception->getMessage(),
                $exception->getFile(),
                $exception->getLine(),
                $exception->getTraceAsString()
            );
        } else {
            $this->displayGenericError();
        }
    }
    
    /**
     * Handle fatal errors
     */
    public function handleFatalError() {
        $error = error_get_last();
        
        if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $this->logError($error['type'], $error['message'], $error['file'], $error['line']);
            
            if ($this->config['displayErrors']) {
                $this->displayError($error['type'], $error['message'], $error['file'], $error['line']);
            } else {
                $this->displayGenericError();
            }
        }
    }
    
    /**
     * Log error to file
     */
    private function logError($errno, $errstr, $errfile, $errline, $trace = '') {
        $errorType = $this->getErrorType($errno);
        $timestamp = date('Y-m-d H:i:s');
        $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        $requestURI = $_SERVER['REQUEST_URI'] ?? 'Unknown';
        
        $logMessage = "[$timestamp] [$clientIP] [$requestURI] [$errorType] $errstr in $errfile on line $errline";
        
        if (!empty($trace)) {
            $logMessage .= "\nStack trace:\n$trace";
        }
        
        error_log($logMessage);
    }
    
    /**
     * Display error (for development)
     */
    private function displayError($errno, $errstr, $errfile, $errline, $trace = '') {
        $errorType = $this->getErrorType($errno);
        
        echo "<div style='background-color:#f8d7da;color:#721c24;padding:10px;margin:10px;border:1px solid #f5c6cb;border-radius:4px;'>";
        echo "<h3>$errorType</h3>";
        echo "<p><strong>Message:</strong> $errstr</p>";
        echo "<p><strong>File:</strong> $errfile</p>";
        echo "<p><strong>Line:</strong> $errline</p>";
        
        if (!empty($trace)) {
            echo "<h4>Stack Trace:</h4>";
            echo "<pre>$trace</pre>";
        }
        
        echo "</div>";
    }
    
    /**
     * Display generic error (for production)
     */
    private function displayGenericError() {
        // Check if this is an API request
        $isApi = (strpos($_SERVER['REQUEST_URI'], '/api/') !== false) || 
                 (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);
        
        if ($isApi) {
            // Return JSON error
            header('Content-Type: application/json');
            http_response_code(500);
            echo json_encode(['error' => 'An internal server error occurred']);
        } else {
            // Return HTML error
            http_response_code(500);
            echo "<div style='text-align:center;padding:40px;'>";
            echo "<h1>Oops! Something went wrong</h1>";
            echo "<p>We're sorry, but there was an error processing your request.</p>";
            echo "<p>Please try again later or contact support if the problem persists.</p>";
            echo "</div>";
        }
    }
    
    /**
     * Get error type string
     */
    private function getErrorType($errno) {
        switch ($errno) {
            case E_ERROR: return 'Fatal Error';
            case E_WARNING: return 'Warning';
            case E_PARSE: return 'Parse Error';
            case E_NOTICE: return 'Notice';
            case E_CORE_ERROR: return 'Core Error';
            case E_CORE_WARNING: return 'Core Warning';
            case E_COMPILE_ERROR: return 'Compile Error';
            case E_COMPILE_WARNING: return 'Compile Warning';
            case E_USER_ERROR: return 'User Error';
            case E_USER_WARNING: return 'User Warning';
            case E_USER_NOTICE: return 'User Notice';
            case E_STRICT: return 'Strict Notice';
            case E_RECOVERABLE_ERROR: return 'Recoverable Error';
            case E_DEPRECATED: return 'Deprecated';
            case E_USER_DEPRECATED: return 'User Deprecated';
            default: return 'Unknown Error';
        }
    }
}

/**
 * Security Headers Manager
 */
class SecurityHeadersManager {
    private $headers;
    
    public function __construct($headers) {
        $this->headers = $headers;
    }
    
    /**
     * Apply all security headers
     */
    public function applyHeaders() {
        foreach ($this->headers as $name => $value) {
            header("$name: $value");
        }
    }
}

/**
 * Password Policy Manager
 */
class PasswordPolicyManager {
    private $config;
    
    public function __construct($config) {
        $this->config = $config;
    }
    
    /**
     * Validate password against policy
     * @param string $password Password to validate
     * @return array Result with status and message
     */
    public function validatePassword($password) {
        $result = ['valid' => true, 'message' => ''];
        
        // Check length
        if (strlen($password) < $this->config['minLength']) {
            $result['valid'] = false;
            $result['message'] = "Password must be at least {$this->config['minLength']} characters long";
            return $result;
        }
        
        // Check for uppercase letters
        if ($this->config['requireUppercase'] && !preg_match('/[A-Z]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one uppercase letter';
            return $result;
        }
        
        // Check for lowercase letters
        if ($this->config['requireLowercase'] && !preg_match('/[a-z]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one lowercase letter';
            return $result;
        }
        
        // Check for numbers
        if ($this->config['requireNumbers'] && !preg_match('/[0-9]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one number';
            return $result;
        }
        
        // Check for special characters
        if ($this->config['requireSpecialChars'] && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $result['valid'] = false;
            $result['message'] = 'Password must contain at least one special character';
            return $result;
        }
        
        return $result;
    }
    
    /**
     * Check if password needs to be changed based on age
     * @param string $lastChanged Timestamp when password was last changed
     * @return bool True if password needs to be changed, false otherwise
     */
    public function passwordNeedsChange($lastChanged) {
        if ($this->config['maxAge'] <= 0) {
            return false;
        }
        
        $maxAgeSeconds = $this->config['maxAge'] * 24 * 60 * 60; // Convert days to seconds
        return (time() - strtotime($lastChanged)) > $maxAgeSeconds;
    }
}

// Initialize security components
function initSecurity() {
    global $securityConfig;
    
    // Apply security headers
    $headersManager = new SecurityHeadersManager($securityConfig['securityHeaders']);
    $headersManager->applyHeaders();
    
    // Initialize error handler
    $errorHandler = new SecureErrorHandler($securityConfig['errorHandling']);
    
    // Initialize CSRF protection
    $csrf = new CSRFProtection($securityConfig['csrf']);
    
    // Check CSRF token for non-GET requests
    if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $_SERVER['REQUEST_METHOD'] !== 'OPTIONS') {
        // Exclude certain paths from CSRF protection (like API endpoints with their own auth)
        $excludedPaths = [
            '/api/auth', // Auth endpoints have their own protection
            '/webhook/' // Webhooks need to be accessible
        ];
        
        if (!$csrf->protectAgainstCSRF($excludedPaths)) {
            // CSRF validation failed
            if (strpos($_SERVER['REQUEST_URI'], '/api/') !== false) {
                // API request
                header('Content-Type: application/json');
                http_response_code(403);
                echo json_encode(['error' => 'CSRF validation failed']);
            } else {
                // Regular request
                http_response_code(403);
                echo "<h1>403 Forbidden</h1><p>CSRF validation failed</p>";
            }
            exit;
        }
    }
    
    // Initialize rate limiter if we have a database connection
    if (function_exists('getDbConnection')) {
        $conn = getDbConnection();
        if ($conn) {
            $rateLimiter = new RateLimiter($securityConfig['rateLimit'], $conn);
            $endpoint = $_SERVER['REQUEST_URI'];
            
            // Check rate limit
            $isAllowed = $rateLimiter->isAllowed($endpoint);
            if (!$isAllowed) {
                $rateLimiter->applyHeaders(true);
                
                if (strpos($endpoint, '/api/') !== false) {
                    // API request
                    echo json_encode(['error' => 'Rate limit exceeded. Please try again later.']);
                } else {
                    // Regular request
                    echo "<h1>429 Too Many Requests</h1><p>Rate limit exceeded. Please try again later.</p>";
                }
                exit;
            }
            
            // Apply rate limit headers
            $rateLimiter->applyHeaders(false);
        }
    }
    
    return [
        'csrf' => $csrf,
        'validator' => new InputValidator(),
        'passwordPolicy' => new PasswordPolicyManager($securityConfig['passwordPolicy'])
    ];
}

// Return security components
return initSecurity();
?>