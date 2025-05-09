<?php
// Database configuration
$host = 'localhost';
$dbname = 'portfolio';
$username = 'root';
$password = '';

// Set headers for JSON response
header('Content-Type: application/json');

try {
    // Create database connection
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    
    // Set PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Prepare SQL statement to fetch all projects
    $stmt = $conn->prepare("SELECT * FROM projects ORDER BY created_at DESC");
    
    // Execute the statement
    $stmt->execute();
    
    // Fetch all projects as associative array
    $projects = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Return projects as JSON
    echo json_encode(['success' => true, 'projects' => $projects]);
} catch(PDOException $e) {
    // Return error response
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}

// Close connection
$conn = null;
?>