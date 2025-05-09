<?php
// Include database configuration
require_once 'db_config.php';

// Set headers for JSON response
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Get request method and path
$method = $_SERVER['REQUEST_METHOD'];
$request = isset($_GET['action']) ? $_GET['action'] : '';

// Check for authentication
require_once 'auth.php';
$token = getBearerToken();
$isAdmin = false;
$userId = null;

if ($token) {
    $isValid = validateToken($token);
    if ($isValid) {
        $userId = $isValid['sub'];
        if (isset($isValid['role']) && $isValid['role'] === 'admin') {
            $isAdmin = true;
        }
    }
}

// Route the request
switch ($method) {
    case 'GET':
        if ($request === 'users') {
            // Only admin can view all users
            if (!$isAdmin) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            // Get all users or specific user
            if (isset($_GET['id'])) {
                getUser($_GET['id']);
            } else {
                getUsers();
            }
        } elseif ($request === 'profile') {
            // Get current user profile
            if (!$userId) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            getUserProfile($userId);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'POST':
        if ($request === 'users') {
            // Only admin can create users
            if (!$isAdmin) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            // Create new user
            createUser();
        } elseif ($request === 'register') {
            // Register new user from Auth0
            registerUser();
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'PUT':
        if ($request === 'users' && isset($_GET['id'])) {
            // Only admin can update other users
            if (!$isAdmin && $_GET['id'] !== $userId) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            // Update user
            updateUser($_GET['id']);
        } elseif ($request === 'profile') {
            // Update current user profile
            if (!$userId) {
                http_response_code(401);
                echo json_encode(['error' => 'Unauthorized']);
                exit;
            }
            
            updateUserProfile($userId);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'DELETE':
        // Only admin can delete users
        if (!$isAdmin) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        
        if ($request === 'users' && isset($_GET['id'])) {
            // Delete user
            deleteUser($_GET['id']);
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
 * Get all users
 */
function getUsers() {
    try {
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $sql = "SELECT id, auth0_id, email, name, role, created_at FROM users ORDER BY created_at DESC";
        
        // Execute query
        $stmt = $conn->prepare($sql);
        $stmt->execute();
        
        // Fetch all users
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Return users as JSON
        echo json_encode(['success' => true, 'users' => $users]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Get a specific user by ID
 * @param int $id User ID
 */
function getUser($id) {
    try {
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $stmt = $conn->prepare("SELECT id, auth0_id, email, name, role, created_at FROM users WHERE id = :id");
        
        // Execute query with parameters
        $stmt->execute([':id' => $id]);
        
        // Fetch user
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Return user as JSON
            echo json_encode(['success' => true, 'user' => $user]);
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
        }
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Get current user profile
 * @param string $auth0Id Auth0 user ID
 */
function getUserProfile($auth0Id) {
    try {
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $stmt = $conn->prepare("SELECT id, auth0_id, email, name, role, created_at FROM users WHERE auth0_id = :auth0_id");
        
        // Execute query with parameters
        $stmt->execute([':auth0_id' => $auth0Id]);
        
        // Fetch user
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Return user as JSON
            echo json_encode(['success' => true, 'profile' => $user]);
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User profile not found']);
        }
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Create a new user
 */
function createUser() {
    try {
        // Get JSON data from request body
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate required fields
        if (!isset($data['auth0_id']) || !isset($data['email']) || !isset($data['name'])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Missing required fields']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if user already exists
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE auth0_id = :auth0_id OR email = :email");
        $checkStmt->execute([
            ':auth0_id' => $data['auth0_id'],
            ':email' => $data['email']
        ]);
        
        if ($checkStmt->rowCount() > 0) {
            http_response_code(409);
            echo json_encode(['success' => false, 'message' => 'User already exists']);
            exit;
        }
        
        // Prepare SQL statement
        $sql = "INSERT INTO users (auth0_id, email, name, role) VALUES (:auth0_id, :email, :name, :role)";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':auth0_id' => $data['auth0_id'],
            ':email' => $data['email'],
            ':name' => $data['name'],
            ':role' => isset($data['role']) ? $data['role'] : 'user'
        ]);
        
        // Get the ID of the newly created user
        $userId = $conn->lastInsertId();
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'User created successfully', 'user_id' => $userId]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Register a new user from Auth0
 */
function registerUser() {
    try {
        // Get JSON data from request body
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate required fields
        if (!isset($data['auth0_id']) || !isset($data['email']) || !isset($data['name'])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Missing required fields']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if user already exists
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE auth0_id = :auth0_id");
        $checkStmt->execute([':auth0_id' => $data['auth0_id']]);
        
        if ($checkStmt->rowCount() > 0) {
            // User already exists, return success
            echo json_encode(['success' => true, 'message' => 'User already registered']);
            exit;
        }
        
        // Prepare SQL statement
        $sql = "INSERT INTO users (auth0_id, email, name, role) VALUES (:auth0_id, :email, :name, :role)";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':auth0_id' => $data['auth0_id'],
            ':email' => $data['email'],
            ':name' => $data['name'],
            ':role' => 'user' // Default role for new registrations
        ]);
        
        // Get the ID of the newly created user
        $userId = $conn->lastInsertId();
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'User registered successfully', 'user_id' => $userId]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Update an existing user
 * @param int $id User ID
 */
function updateUser($id) {
    try {
        // Get JSON data from request body
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate user ID
        if (!$id) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'User ID is required']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if user exists
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE id = :id");
        $checkStmt->execute([':id' => $id]);
        
        if ($checkStmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
            exit;
        }
        
        // Build update SQL statement dynamically based on provided fields
        $updateFields = [];
        $params = [':id' => $id];
        
        if (isset($data['email'])) {
            $updateFields[] = "email = :email";
            $params[':email'] = $data['email'];
        }
        
        if (isset($data['name'])) {
            $updateFields[] = "name = :name";
            $params[':name'] = $data['name'];
        }
        
        if (isset($data['role'])) {
            $updateFields[] = "role = :role";
            $params[':role'] = $data['role'];
        }
        
        // If no fields to update, return error
        if (empty($updateFields)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'No fields to update']);
            exit;
        }
        
        // Prepare SQL statement
        $sql = "UPDATE users SET " . implode(", ", $updateFields) . " WHERE id = :id";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'User updated successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Update current user profile
 * @param string $auth0Id Auth0 user ID
 */
function updateUserProfile($auth0Id) {
    try {
        // Get JSON data from request body
        $data = json_decode(file_get_contents('php://input'), true);
        
        $conn = getDbConnection();
        
        // Check if user exists
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE auth0_id = :auth0_id");
        $checkStmt->execute([':auth0_id' => $auth0Id]);
        
        if ($checkStmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
            exit;
        }
        
        // Build update SQL statement dynamically based on provided fields
        $updateFields = [];
        $params = [':auth0_id' => $auth0Id];
        
        if (isset($data['email'])) {
            $updateFields[] = "email = :email";
            $params[':email'] = $data['email'];
        }
        
        if (isset($data['name'])) {
            $updateFields[] = "name = :name";
            $params[':name'] = $data['name'];
        }
        
        // If no fields to update, return error
        if (empty($updateFields)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'No fields to update']);
            exit;
        }
        
        // Prepare SQL statement
        $sql = "UPDATE users SET " . implode(", ", $updateFields) . " WHERE auth0_id = :auth0_id";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Profile updated successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Delete a user
 * @param int $id User ID
 */
function deleteUser($id) {
    try {
        // Validate user ID
        if (!$id) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'User ID is required']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if user exists
        $checkStmt = $conn->prepare("SELECT id FROM users WHERE id = :id");
        $checkStmt->execute([':id' => $id]);
        
        if ($checkStmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found']);
            exit;
        }
        
        // Prepare SQL statement
        $stmt = $conn->prepare("DELETE FROM users WHERE id = :id");
        
        // Execute query with parameters
        $stmt->execute([':id' => $id]);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'User deleted successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}
?>