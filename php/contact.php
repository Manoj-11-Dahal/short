<?php
// Include database configuration
require_once 'db_config.php';

// Set headers for JSON response
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Function to sanitize input data
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get and sanitize form data
    $name = isset($_POST['name']) ? sanitize_input($_POST['name']) : '';
    $email = isset($_POST['email']) ? sanitize_input($_POST['email']) : '';
    $message = isset($_POST['message']) ? sanitize_input($_POST['message']) : '';
    $timestamp = date('Y-m-d H:i:s');
    
    // Validate form data
    if (empty($name) || empty($email) || empty($message)) {
        echo json_encode(['success' => false, 'message' => 'Please fill in all fields']);
        exit;
    }
    
    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => 'Please enter a valid email address']);
        exit;
    }
    
    try {
        // Get subject from form data
        $subject = isset($_POST['subject']) ? sanitize_input($_POST['subject']) : '';
        
        // Prepare SQL statement
        $sql = "INSERT INTO contact_messages (name, email, subject, message, timestamp) VALUES (:name, :email, :subject, :message, :timestamp)";
        
        // Execute query with parameters
        $result = executeQuery($sql, [
            ':name' => $name,
            ':email' => $email,
            ':subject' => $subject,
            ':message' => $message,
            ':timestamp' => $timestamp
        ]);
        
        // Execute the statement
        $stmt->execute();
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Message sent successfully!']);
    } catch(PDOException $e) {
        // Return error response
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
    
    // Close connection
    $conn = null;
} else {
    // Return error for non-POST requests
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
}
?>