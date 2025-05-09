<?php
/**
 * Rate Limiter Implementation
 * 
 * This file provides functions for rate limiting API requests
 * to prevent abuse, brute force attacks, and DoS attempts.
 */

/**
 * Rate Limiter Class
 * 
 * Implements rate limiting for API endpoints using database storage
 */
class RateLimiter {
    private $conn;           // Database connection
    private $tableName;      // Table name for storing rate limit data
    private $maxRequests;    // Maximum number of requests allowed in time window
    private $timeWindow;     // Time window in seconds
    private $ipHeaderName;   // Header name for getting client IP (for proxies)
    
    /**
     * Constructor
     * 
     * @param PDO $conn Database connection
     * @param int $maxRequests Maximum requests allowed in time window
     * @param int $timeWindow Time window in seconds
     * @param string $tableName Table name for storing rate limit data
     * @param string $ipHeaderName Header name for getting client IP
     */
    public function __construct($conn, $maxRequests = 60, $timeWindow = 60, $tableName = 'rate_limits', $ipHeaderName = 'X-Forwarded-For') {
        $this->conn = $conn;
        $this->maxRequests = $maxRequests;
        $this->timeWindow = $timeWindow;
        $this->tableName = $tableName;
        $this->ipHeaderName = $ipHeaderName;
        
        // Create rate limits table if it doesn't exist
        $this->createTable();
    }
    
    /**
     * Create rate limits table if it doesn't exist
     */
    private function createTable() {
        try {
            $this->conn->exec("CREATE TABLE IF NOT EXISTS {$this->tableName} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45) NOT NULL,
                endpoint VARCHAR(255) NOT NULL,
                request_time INT NOT NULL,
                INDEX idx_ip_endpoint (ip, endpoint)
            )");
        } catch (PDOException $e) {
            error_log("Failed to create rate limit table: " . $e->getMessage());
        }
    }
    
    /**
     * Get client IP address
     * 
     * @return string Client IP address
     */
    private function getClientIP() {
        if (!empty($_SERVER[$this->ipHeaderName])) {
            // Get the first IP if multiple are provided
            $ips = explode(',', $_SERVER[$this->ipHeaderName]);
            return trim($ips[0]);
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Clean up old rate limit entries
     */
    private function cleanupOldEntries() {
        try {
            $cutoff = time() - $this->timeWindow;
            $stmt = $this->conn->prepare("DELETE FROM {$this->tableName} WHERE request_time < :cutoff");
            $stmt->bindParam(':cutoff', $cutoff, PDO::PARAM_INT);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log("Failed to clean up old rate limit entries: " . $e->getMessage());
        }
    }
    
    /**
     * Check if request is allowed based on rate limits
     * 
     * @param string $endpoint Endpoint being accessed
     * @return bool True if request is allowed, false if rate limited
     */
    public function isAllowed($endpoint = '') {
        $ip = $this->getClientIP();
        $now = time();
        $windowStart = $now - $this->timeWindow;
        
        try {
            // Clean up old entries periodically (1% chance to reduce DB load)
            if (rand(1, 100) === 1) {
                $this->cleanupOldEntries();
            }
            
            // Count requests in current window
            $stmt = $this->conn->prepare("SELECT COUNT(*) FROM {$this->tableName} 
                                         WHERE ip = :ip AND endpoint = :endpoint 
                                         AND request_time >= :windowStart");
            $stmt->bindParam(':ip', $ip, PDO::PARAM_STR);
            $stmt->bindParam(':endpoint', $endpoint, PDO::PARAM_STR);
            $stmt->bindParam(':windowStart', $windowStart, PDO::PARAM_INT);
            $stmt->execute();
            
            $count = $stmt->fetchColumn();
            
            // Check if limit exceeded
            if ($count >= $this->maxRequests) {
                return false;
            }
            
            // Record this request
            $stmt = $this->conn->prepare("INSERT INTO {$this->tableName} (ip, endpoint, request_time) 
                                         VALUES (:ip, :endpoint, :requestTime)");
            $stmt->bindParam(':ip', $ip, PDO::PARAM_STR);
            $stmt->bindParam(':endpoint', $endpoint, PDO::PARAM_STR);
            $stmt->bindParam(':requestTime', $now, PDO::PARAM_INT);
            $stmt->execute();
            
            return true;
        } catch (PDOException $e) {
            // Log error but don't block request if rate limiting fails
            error_log("Rate limiting error: " . $e->getMessage());
            return true;
        }
    }
    
    /**
     * Apply rate limiting headers to response
     * 
     * @param bool $isLimited Whether request is rate limited
     */
    public function applyHeaders($isLimited = false) {
        // Get current usage
        $ip = $this->getClientIP();
        $endpoint = $_SERVER['REQUEST_URI'] ?? '';
        $windowStart = time() - $this->timeWindow;
        $remaining = $this->maxRequests;
        
        try {
            $stmt = $this->conn->prepare("SELECT COUNT(*) FROM {$this->tableName} 
                                         WHERE ip = :ip AND endpoint = :endpoint 
                                         AND request_time >= :windowStart");
            $stmt->bindParam(':ip', $ip, PDO::PARAM_STR);
            $stmt->bindParam(':endpoint', $endpoint, PDO::PARAM_STR);
            $stmt->bindParam(':windowStart', $windowStart, PDO::PARAM_INT);
            $stmt->execute();
            
            $count = $stmt->fetchColumn();
            $remaining = max(0, $this->maxRequests - $count);
        } catch (PDOException $e) {
            error_log("Error getting rate limit count: " . $e->getMessage());
        }
        
        // Set rate limit headers
        header('X-RateLimit-Limit: ' . $this->maxRequests);
        header('X-RateLimit-Remaining: ' . $remaining);
        header('X-RateLimit-Reset: ' . (time() + $this->timeWindow));
        
        if ($isLimited) {
            header('Retry-After: ' . $this->timeWindow);
            http_response_code(429); // Too Many Requests
        }
    }
    
    /**
     * Check and enforce rate limits
     * 
     * @param string $endpoint Endpoint being accessed
     * @param array $options Additional options
     * @return bool True if request is allowed, false if rate limited
     */
    public function enforce($endpoint = '', $options = []) {
        // Default options
        $defaultOptions = [
            'sendHeaders' => true,       // Whether to send rate limit headers
            'sendErrorResponse' => true, // Whether to send error response if limited
            'customMessage' => null      // Custom error message
        ];
        
        $options = array_merge($defaultOptions, $options);
        
        // Check if request is allowed
        $isAllowed = $this->isAllowed($endpoint);
        
        // Apply headers if enabled
        if ($options['sendHeaders']) {
            $this->applyHeaders(!$isAllowed);
        }
        
        // Send error response if rate limited and enabled
        if (!$isAllowed && $options['sendErrorResponse']) {
            $message = $options['customMessage'] ?? 'Rate limit exceeded. Please try again later.';
            
            // Determine response format
            $isApiRequest = (strpos($endpoint, '/api/') !== false) || 
                           (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);
            
            if ($isApiRequest) {
                // API request - return JSON error
                header('Content-Type: application/json');
                echo json_encode(['error' => $message]);
            } else {
                // Regular request - return HTML error
                echo "<h1>429 Too Many Requests</h1>";
                echo "<p>$message</p>";
                echo "<p>Please wait and try again later.</p>";
            }
            exit;
        }
        
        return $isAllowed;
    }
}

/**
 * Create a rate limiter instance with default configuration
 * 
 * @param PDO $conn Database connection
 * @return RateLimiter Rate limiter instance
 */
function createRateLimiter($conn) {
    // Default configuration
    $config = [
        'maxRequests' => 60,           // 60 requests per minute for general endpoints
        'timeWindow' => 60,             // 1 minute window
        'tableName' => 'rate_limits',   // Table name
        'ipHeaderName' => 'HTTP_X_FORWARDED_FOR' // Header name for proxies
    ];
    
    return new RateLimiter(
        $conn,
        $config['maxRequests'],
        $config['timeWindow'],
        $config['tableName'],
        $config['ipHeaderName']
    );
}

/**
 * Helper function to enforce rate limits for sensitive endpoints
 * 
 * @param PDO $conn Database connection
 * @param string $endpoint Endpoint identifier
 * @param int $maxRequests Maximum requests allowed
 * @param int $timeWindow Time window in seconds
 */
function enforceStrictRateLimit($conn, $endpoint, $maxRequests = 10, $timeWindow = 60) {
    $rateLimiter = new RateLimiter($conn, $maxRequests, $timeWindow);
    $rateLimiter->enforce($endpoint);
}

/**
 * Helper function to enforce rate limits for login attempts
 * 
 * @param PDO $conn Database connection
 * @param string $username Username being used for login
 */
function enforceLoginRateLimit($conn, $username) {
    // Stricter limits for login attempts (5 per minute)
    $endpoint = 'login:' . md5($username); // Hash username to avoid exposing it
    enforceStrictRateLimit($conn, $endpoint, 5, 60);
}
?>