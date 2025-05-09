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
        if ($request === 'posts') {
            // Get all published posts or specific post
            if (isset($_GET['id'])) {
                getPost($_GET['id']);
            } elseif (isset($_GET['slug'])) {
                getPostBySlug($_GET['slug']);
            } else {
                getPosts();
            }
        } elseif ($request === 'categories') {
            // Get all categories
            getCategories();
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'POST':
        // Check admin access for POST operations
        if (!$isAdmin) {
            http_response_code(403);
            echo json_encode(['error' => 'Unauthorized access']);
            exit;
        }
        
        if ($request === 'posts') {
            // Create new post
            createPost();
        } elseif ($request === 'categories') {
            // Create new category
            createCategory();
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'PUT':
        // Check admin access for PUT operations
        if (!$isAdmin) {
            http_response_code(403);
            echo json_encode(['error' => 'Unauthorized access']);
            exit;
        }
        
        if ($request === 'posts' && isset($_GET['id'])) {
            // Update existing post
            updatePost($_GET['id']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
        }
        break;
        
    case 'DELETE':
        // Check admin access for DELETE operations
        if (!$isAdmin) {
            http_response_code(403);
            echo json_encode(['error' => 'Unauthorized access']);
            exit;
        }
        
        if ($request === 'posts' && isset($_GET['id'])) {
            // Delete post
            deletePost($_GET['id']);
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

// Get all published blog posts
function getPosts() {
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    $category = isset($_GET['category']) ? $_GET['category'] : null;
    
    $sql = "SELECT p.id, p.title, p.slug, p.excerpt, p.featured_image, p.created_at, p.updated_at "
         . "FROM blog_posts p ";
    
    $params = [];
    
    if ($category) {
        $sql .= "JOIN post_categories pc ON p.id = pc.post_id "
             . "JOIN blog_categories c ON pc.category_id = c.id "
             . "WHERE p.status = 'published' AND c.slug = :category ";
        $params[':category'] = $category;
    } else {
        $sql .= "WHERE p.status = 'published' ";
    }
    
    $sql .= "ORDER BY p.created_at DESC LIMIT :limit OFFSET :offset";
    $params[':limit'] = $limit;
    $params[':offset'] = $offset;
    
    $posts = executeQuery($sql, $params);
    
    if ($posts === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to fetch posts']);
        return;
    }
    
    // Get total count for pagination
    $countSql = "SELECT COUNT(*) as total FROM blog_posts WHERE status = 'published'";
    $countResult = executeQuery($countSql);
    $total = $countResult[0]['total'] ?? 0;
    
    echo json_encode([
        'posts' => $posts,
        'total' => (int)$total,
        'limit' => $limit,
        'offset' => $offset
    ]);
}

// Get a specific blog post by ID
function getPost($id) {
    $sql = "SELECT p.*, u.name as author_name "
         . "FROM blog_posts p "
         . "LEFT JOIN users u ON p.author_id = u.id "
         . "WHERE p.id = :id AND p.status = 'published'";
    
    $post = executeQuery($sql, [':id' => $id]);
    
    if ($post === false || empty($post)) {
        http_response_code(404);
        echo json_encode(['error' => 'Post not found']);
        return;
    }
    
    // Get categories for this post
    $categoriesSql = "SELECT c.id, c.name, c.slug "
                   . "FROM blog_categories c "
                   . "JOIN post_categories pc ON c.id = pc.category_id "
                   . "WHERE pc.post_id = :post_id";
    
    $categories = executeQuery($categoriesSql, [':post_id' => $id]);
    
    $post[0]['categories'] = $categories ?: [];
    
    echo json_encode(['post' => $post[0]]);
}

// Get a specific blog post by slug
function getPostBySlug($slug) {
    $sql = "SELECT p.*, u.name as author_name "
         . "FROM blog_posts p "
         . "LEFT JOIN users u ON p.author_id = u.id "
         . "WHERE p.slug = :slug AND p.status = 'published'";
    
    $post = executeQuery($sql, [':slug' => $slug]);
    
    if ($post === false || empty($post)) {
        http_response_code(404);
        echo json_encode(['error' => 'Post not found']);
        return;
    }
    
    // Get categories for this post
    $categoriesSql = "SELECT c.id, c.name, c.slug "
                   . "FROM blog_categories c "
                   . "JOIN post_categories pc ON c.id = pc.category_id "
                   . "WHERE pc.post_id = :post_id";
    
    $categories = executeQuery($categoriesSql, [':post_id' => $post[0]['id']]);
    
    $post[0]['categories'] = $categories ?: [];
    
    echo json_encode(['post' => $post[0]]);
}

// Get all blog categories
function getCategories() {
    $sql = "SELECT * FROM blog_categories ORDER BY name";
    $categories = executeQuery($sql);
    
    if ($categories === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to fetch categories']);
        return;
    }
    
    echo json_encode(['categories' => $categories]);
}

// Create a new blog post
function createPost() {
    // Get JSON data
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!$data || !isset($data['title']) || !isset($data['content'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid post data']);
        return;
    }
    
    // Generate slug from title
    $slug = generateSlug($data['title']);
    
    // Prepare data
    $title = $data['title'];
    $content = $data['content'];
    $excerpt = isset($data['excerpt']) ? $data['excerpt'] : substr(strip_tags($content), 0, 150) . '...';
    $featuredImage = $data['featured_image'] ?? null;
    $authorId = $data['author_id'] ?? null;
    $status = $data['status'] ?? 'draft';
    
    // Insert post
    $sql = "INSERT INTO blog_posts (title, slug, content, excerpt, featured_image, author_id, status) "
         . "VALUES (:title, :slug, :content, :excerpt, :featured_image, :author_id, :status)";
    
    $result = executeQuery($sql, [
        ':title' => $title,
        ':slug' => $slug,
        ':content' => $content,
        ':excerpt' => $excerpt,
        ':featured_image' => $featuredImage,
        ':author_id' => $authorId,
        ':status' => $status
    ]);
    
    if ($result === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create post']);
        return;
    }
    
    $postId = getLastInsertId();
    
    // Handle categories if provided
    if (isset($data['categories']) && is_array($data['categories'])) {
        foreach ($data['categories'] as $categoryId) {
            $catSql = "INSERT INTO post_categories (post_id, category_id) VALUES (:post_id, :category_id)";
            executeQuery($catSql, [':post_id' => $postId, ':category_id' => $categoryId]);
        }
    }
    
    http_response_code(201);
    echo json_encode([
        'success' => true,
        'message' => 'Post created successfully',
        'post_id' => $postId
    ]);
}

// Update an existing blog post
function updatePost($id) {
    // Get JSON data
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!$data) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid post data']);
        return;
    }
    
    // Check if post exists
    $checkSql = "SELECT id FROM blog_posts WHERE id = :id";
    $post = executeQuery($checkSql, [':id' => $id]);
    
    if ($post === false || empty($post)) {
        http_response_code(404);
        echo json_encode(['error' => 'Post not found']);
        return;
    }
    
    // Build update query
    $updateFields = [];
    $params = [':id' => $id];
    
    if (isset($data['title'])) {
        $updateFields[] = "title = :title";
        $params[':title'] = $data['title'];
        
        // Update slug if title changes
        $updateFields[] = "slug = :slug";
        $params[':slug'] = generateSlug($data['title']);
    }
    
    if (isset($data['content'])) {
        $updateFields[] = "content = :content";
        $params[':content'] = $data['content'];
        
        // Update excerpt if not provided but content changes
        if (!isset($data['excerpt'])) {
            $updateFields[] = "excerpt = :excerpt";
            $params[':excerpt'] = substr(strip_tags($data['content']), 0, 150) . '...';
        }
    }
    
    if (isset($data['excerpt'])) {
        $updateFields[] = "excerpt = :excerpt";
        $params[':excerpt'] = $data['excerpt'];
    }
    
    if (isset($data['featured_image'])) {
        $updateFields[] = "featured_image = :featured_image";
        $params[':featured_image'] = $data['featured_image'];
    }
    
    if (isset($data['status'])) {
        $updateFields[] = "status = :status";
        $params[':status'] = $data['status'];
    }
    
    if (empty($updateFields)) {
        http_response_code(400);
        echo json_encode(['error' => 'No fields to update']);
        return;
    }
    
    // Execute update
    $sql = "UPDATE blog_posts SET " . implode(", ", $updateFields) . " WHERE id = :id";
    $result = executeQuery($sql, $params);
    
    if ($result === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update post']);
        return;
    }
    
    // Update categories if provided
    if (isset($data['categories']) && is_array($data['categories'])) {
        // Remove existing categories
        $deleteCatSql = "DELETE FROM post_categories WHERE post_id = :post_id";
        executeQuery($deleteCatSql, [':post_id' => $id]);
        
        // Add new categories
        foreach ($data['categories'] as $categoryId) {
            $catSql = "INSERT INTO post_categories (post_id, category_id) VALUES (:post_id, :category_id)";
            executeQuery($catSql, [':post_id' => $id, ':category_id' => $categoryId]);
        }
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Post updated successfully'
    ]);
}

// Delete a blog post
function deletePost($id) {
    // Check if post exists
    $checkSql = "SELECT id FROM blog_posts WHERE id = :id";
    $post = executeQuery($checkSql, [':id' => $id]);
    
    if ($post === false || empty($post)) {
        http_response_code(404);
        echo json_encode(['error' => 'Post not found']);
        return;
    }
    
    // Delete post categories first (due to foreign key constraint)
    $deleteCatSql = "DELETE FROM post_categories WHERE post_id = :post_id";
    executeQuery($deleteCatSql, [':post_id' => $id]);
    
    // Delete post
    $sql = "DELETE FROM blog_posts WHERE id = :id";
    $result = executeQuery($sql, [':id' => $id]);
    
    if ($result === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to delete post']);
        return;
    }
    
    echo json_encode([
        'success' => true,
        'message' => 'Post deleted successfully'
    ]);
}

// Create a new category
function createCategory() {
    // Get JSON data
    $data = json_decode(file_get_contents('php://input'), true);
    
    if (!$data || !isset($data['name'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid category data']);
        return;
    }
    
    // Generate slug from name
    $slug = generateSlug($data['name']);
    
    // Insert category
    $sql = "INSERT INTO blog_categories (name, slug) VALUES (:name, :slug)";
    $result = executeQuery($sql, [':name' => $data['name'], ':slug' => $slug]);
    
    if ($result === false) {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to create category']);
        return;
    }
    
    $categoryId = getLastInsertId();
    
    http_response_code(201);
    echo json_encode([
        'success' => true,
        'message' => 'Category created successfully',
        'category_id' => $categoryId
    ]);
}

// Helper function to generate slug from string
function generateSlug($string) {
    // Replace non letter or digits by -
    $string = preg_replace('~[^\pL\d]+~u', '-', $string);
    // Transliterate
    $string = iconv('utf-8', 'us-ascii//TRANSLIT', $string);
    // Remove unwanted characters
    $string = preg_replace('~[^-\w]+~', '', $string);
    // Trim
    $string = trim($string, '-');
    // Remove duplicate -
    $string = preg_replace('~-+~', '-', $string);
    // Lowercase
    $string = strtolower($string);
    
    if (empty($string)) {
        return 'n-a';
    }
    
    return $string;
}

// Helper function to get bearer token from header
function getBearerToken() {
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER['Authorization']);
    } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    
    if (!empty($headers) && preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
        return $matches[1];
    }
    
    return null;
}