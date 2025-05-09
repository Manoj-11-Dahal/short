<?php
// Include database configuration
require_once 'db_config.php';

// Set headers for JSON response
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, DELETE');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$request = isset($_GET['action']) ? $_GET['action'] : '';

// Check for authentication for admin operations
require_once 'auth.php';
$token = getBearerToken();
$isAdmin = false;

if ($token) {
    $isValid = validateToken($token);
    if ($isValid && isset($isValid['role']) && $isValid['role'] === 'admin') {
        $isAdmin = true;
    }
}

// Function to sanitize input data
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Route the request
switch ($method) {
    case 'GET':
        // Only admin can view messages
        if (!$isAdmin) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        
        if ($request === 'messages') {
            // Get all messages or specific message
            if (isset($_GET['id'])) {
                getMessage($_GET['id']);
            } else {
                getMessages();
            }
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'POST':
        if ($request === 'messages') {
            // Submit contact form
            submitContactForm();
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'DELETE':
        // Only admin can delete messages
        if (!$isAdmin) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        
        if ($request === 'messages' && isset($_GET['id'])) {
            // Delete message
            deleteMessage($_GET['id']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

/**
 * Submit contact form
 */
function submitContactForm() {
    try {
        // Get form data
        $name = isset($_POST['name']) ? sanitize_input($_POST['name']) : '';
        $email = isset($_POST['email']) ? sanitize_input($_POST['email']) : '';
        $subject = isset($_POST['subject']) ? sanitize_input($_POST['subject']) : '';
        $message = isset($_POST['message']) ? sanitize_input($_POST['message']) : '';
        $timestamp = date('Y-m-d H:i:s');
        
        // Validate form data
        if (empty($name) || empty($email) || empty($subject) || empty($message)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Please fill in all fields']);
            exit;
        }
        
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Please enter a valid email address']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $sql = "INSERT INTO contact_messages (name, email, subject, message, timestamp, is_read) "
             . "VALUES (:name, :email, :subject, :message, :timestamp, :is_read)";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':name' => $name,
            ':email' => $email,
            ':subject' => $subject,
            ':message' => $message,
            ':timestamp' => $timestamp,
            ':is_read' => false
        ]);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Your message has been sent successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Get all messages
 */
function getMessages() {
    try {
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $sql = "SELECT * FROM contact_messages ORDER BY timestamp DESC";
        
        // Execute query
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        
        // Fetch all messages
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Return messages as JSON
        echo json_encode(['success' => true, 'messages' => $messages]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Get a specific message by ID
 * @param int $id Message ID
 */
function getMessage($id) {
    try {
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $stmt = $conn->prepare("SELECT * FROM contact_messages WHERE id = :id");
        
        // Execute query with parameters
        $stmt->execute([':id' => $id]);
        
        // Fetch message
        $message = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($message) {
            // Mark message as read
            if (!$message['is_read']) {
                $updateStmt = $conn->prepare("UPDATE contact_messages SET is_read = TRUE WHERE id = :id");
                $updateStmt->execute([':id' => $id]);
            }
            
            // Return message as JSON
            echo json_encode(['success' => true, 'message' => $message]);
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Message not found']);
        }
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Delete a message
 * @param int $id Message ID
 */
function deleteMessage($id) {
    try {
        // Validate message ID
        if (!$id) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Message ID is required']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if message exists
        $checkStmt = $conn->prepare("SELECT id FROM contact_messages WHERE id = :id");
        $checkStmt->execute([':id' => $id]);
        
        if ($checkStmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Message not found']);
            exit;
        }
        
        // Prepare SQL statement
        $stmt = $conn->prepare("DELETE FROM contact_messages WHERE id = :id");
        
        // Execute query with parameters
        $stmt->execute([':id' => $id]);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Message deleted successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}
?>