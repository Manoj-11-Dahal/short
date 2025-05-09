<?php
// Database configuration
$host = 'localhost';
$dbname = 'portfolio';
$username = 'root';
$password = '';

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

/**
 * Get database connection
 * @return PDO Database connection object
 */
function getDbConnection() {
    global $host, $dbname, $username, $password;
    
    try {
        // Create database connection
        $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        
        // Set PDO error mode to exception
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        return $conn;
    } catch(PDOException $e) {
        // Log error (in production, log to file instead of showing)
        error_log("Connection failed: " . $e->getMessage());
        return null;
    }
}

/**
 * Execute a query with parameters
 * @param string $sql SQL query with placeholders
 * @param array $params Parameters for the query
 * @return array|false Result set or false on failure
 */
function executeQuery($sql, $params = []) {
    $conn = getDbConnection();
    if (!$conn) {
        return false;
    }
    
    try {
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        
        // For SELECT queries
        if (stripos($sql, 'SELECT') === 0) {
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        
        // For INSERT, UPDATE, DELETE queries
        return true;
    } catch(PDOException $e) {
        error_log("Query execution failed: " . $e->getMessage());
        return false;
    }
}

/**
 * Get last inserted ID
 * @return int|false Last inserted ID or false on failure
 */
function getLastInsertId() {
    $conn = getDbConnection();
    if (!$conn) {
        return false;
    }
    
    return $conn->lastInsertId();
}