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

if ($token) {
    $isValid = validateToken($token);
    if ($isValid && isset($isValid['role']) && $isValid['role'] === 'admin') {
        $isAdmin = true;
    }
}

// Route the request
switch ($method) {
    case 'GET':
        if ($request === 'projects') {
            // Get all projects or specific project
            if (isset($_GET['id'])) {
                getProject($_GET['id']);
            } else {
                getProjects();
            }
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'POST':
        // Check if user is admin
        if (!$isAdmin) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        
        if ($request === 'projects') {
            // Create new project
            createProject();
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'PUT':
        // Check if user is admin
        if (!$isAdmin) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        
        if ($request === 'projects' && isset($_GET['id'])) {
            // Update project
            updateProject($_GET['id']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'DELETE':
        // Check if user is admin
        if (!$isAdmin) {
            http_response_code(401);
            echo json_encode(['error' => 'Unauthorized']);
            exit;
        }
        
        if ($request === 'projects' && isset($_GET['id'])) {
            // Delete project
            deleteProject($_GET['id']);
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
 * Get all projects
 */
function getProjects() {
    try {
        $conn = getDbConnection();
        
        // Check if featured filter is applied
        $featured = isset($_GET['featured']) ? (bool)$_GET['featured'] : null;
        
        // Prepare SQL statement
        $sql = "SELECT * FROM projects";
        $params = [];
        
        if ($featured !== null) {
            $sql .= " WHERE featured = :featured";
            $params[':featured'] = $featured ? 1 : 0;
        }
        
        $sql .= " ORDER BY created_at DESC";
        
        // Execute query
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        
        // Fetch all projects
        $projects = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Return projects as JSON
        echo json_encode(['success' => true, 'projects' => $projects]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Get a specific project by ID
 * @param int $id Project ID
 */
function getProject($id) {
    try {
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $stmt = $conn->prepare("SELECT * FROM projects WHERE id = :id");
        
        // Execute query with parameters
        $stmt->execute([':id' => $id]);
        
        // Fetch project
        $project = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($project) {
            // Return project as JSON
            echo json_encode(['success' => true, 'project' => $project]);
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Project not found']);
        }
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Create a new project
 */
function createProject() {
    try {
        // Get JSON data from request body
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate required fields
        if (!isset($data['title']) || !isset($data['description']) || !isset($data['image_url'])) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Missing required fields']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Prepare SQL statement
        $sql = "INSERT INTO projects (title, description, image_url, project_url, technologies, featured) "
             . "VALUES (:title, :description, :image_url, :project_url, :technologies, :featured)";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute([
            ':title' => $data['title'],
            ':description' => $data['description'],
            ':image_url' => $data['image_url'],
            ':project_url' => isset($data['project_url']) ? $data['project_url'] : null,
            ':technologies' => isset($data['technologies']) ? $data['technologies'] : null,
            ':featured' => isset($data['featured']) ? (bool)$data['featured'] : false
        ]);
        
        // Get the ID of the newly created project
        $projectId = $conn->lastInsertId();
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Project created successfully', 'project_id' => $projectId]);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Update an existing project
 * @param int $id Project ID
 */
function updateProject($id) {
    try {
        // Get JSON data from request body
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate project ID
        if (!$id) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Project ID is required']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if project exists
        $checkStmt = $conn->prepare("SELECT id FROM projects WHERE id = :id");
        $checkStmt->execute([':id' => $id]);
        
        if ($checkStmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Project not found']);
            exit;
        }
        
        // Build update SQL statement dynamically based on provided fields
        $updateFields = [];
        $params = [':id' => $id];
        
        if (isset($data['title'])) {
            $updateFields[] = "title = :title";
            $params[':title'] = $data['title'];
        }
        
        if (isset($data['description'])) {
            $updateFields[] = "description = :description";
            $params[':description'] = $data['description'];
        }
        
        if (isset($data['image_url'])) {
            $updateFields[] = "image_url = :image_url";
            $params[':image_url'] = $data['image_url'];
        }
        
        if (isset($data['project_url'])) {
            $updateFields[] = "project_url = :project_url";
            $params[':project_url'] = $data['project_url'];
        }
        
        if (isset($data['technologies'])) {
            $updateFields[] = "technologies = :technologies";
            $params[':technologies'] = $data['technologies'];
        }
        
        if (isset($data['featured'])) {
            $updateFields[] = "featured = :featured";
            $params[':featured'] = (bool)$data['featured'];
        }
        
        // If no fields to update, return error
        if (empty($updateFields)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'No fields to update']);
            exit;
        }
        
        // Prepare SQL statement
        $sql = "UPDATE projects SET " . implode(", ", $updateFields) . " WHERE id = :id";
        
        // Execute query with parameters
        $stmt = $conn->prepare($sql);
        $stmt->execute($params);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Project updated successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}

/**
 * Delete a project
 * @param int $id Project ID
 */
function deleteProject($id) {
    try {
        // Validate project ID
        if (!$id) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Project ID is required']);
            exit;
        }
        
        $conn = getDbConnection();
        
        // Check if project exists
        $checkStmt = $conn->prepare("SELECT id FROM projects WHERE id = :id");
        $checkStmt->execute([':id' => $id]);
        
        if ($checkStmt->rowCount() === 0) {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Project not found']);
            exit;
        }
        
        // Prepare SQL statement
        $stmt = $conn->prepare("DELETE FROM projects WHERE id = :id");
        
        // Execute query with parameters
        $stmt->execute([':id' => $id]);
        
        // Return success response
        echo json_encode(['success' => true, 'message' => 'Project deleted successfully']);
    } catch(PDOException $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
}
?>