<?php
// Include database configuration
require_once 'db_config.php';

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

// Redirect if not admin
if (!$isAdmin) {
    header('Location: ../index.html');
    exit;
}

// Get dashboard section
$section = isset($_GET['section']) ? $_GET['section'] : 'overview';

// HTML header
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard | Portfolio</title>
    <link rel="stylesheet" href="../css/style.css">
    <link rel="stylesheet" href="../css/auth.css">
    <style>
        .dashboard {
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .dashboard-nav {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .dashboard-nav ul {
            display: flex;
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .dashboard-nav li {
            margin-right: 20px;
        }
        .dashboard-nav a {
            text-decoration: none;
            color: #333;
            font-weight: bold;
        }
        .dashboard-nav a.active {
            color: #007bff;
        }
        .dashboard-content {
            background-color: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        .dashboard-table {
            width: 100%;
            border-collapse: collapse;
        }
        .dashboard-table th, .dashboard-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .dashboard-table th {
            background-color: #f5f5f5;
        }
        .dashboard-form {
            max-width: 600px;
        }
        .dashboard-form label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .dashboard-form input, .dashboard-form textarea, .dashboard-form select {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .dashboard-form textarea {
            height: 200px;
        }
        .dashboard-form button {
            background-color: #007bff;
            color: #fff;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
        }
        .dashboard-form button:hover {
            background-color: #0056b3;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-success {
            background-color: #28a745;
            color: #fff;
        }
        .badge-warning {
            background-color: #ffc107;
            color: #000;
        }
        .action-buttons {
            display: flex;
            gap: 5px;
        }
        .btn-edit, .btn-delete, .btn-view {
            padding: 5px 10px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        .btn-view {
            background-color: #17a2b8;
            color: #fff;
        }
        .btn-edit {
            background-color: #ffc107;
            color: #000;
        }
        .btn-delete {
            background-color: #dc3545;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="dashboard-header">
            <h1>Admin Dashboard</h1>
            <button id="logout-btn" class="btn-delete">Logout</button>
        </div>
        
        <div class="dashboard-nav">
            <ul>
                <li><a href="?section=overview" <?php echo $section === 'overview' ? 'class="active"' : ''; ?>>Overview</a></li>
                <li><a href="?section=messages" <?php echo $section === 'messages' ? 'class="active"' : ''; ?>>Messages</a></li>
                <li><a href="?section=blog" <?php echo $section === 'blog' ? 'class="active"' : ''; ?>>Blog Posts</a></li>
                <li><a href="?section=projects" <?php echo $section === 'projects' ? 'class="active"' : ''; ?>>Projects</a></li>
                <li><a href="?section=users" <?php echo $section === 'users' ? 'class="active"' : ''; ?>>Users</a></li>
            </ul>
        </div>
        
        <div class="dashboard-content">
            <?php
            // Display different content based on section
            switch ($section) {
                case 'overview':
                    include 'dashboard/overview.php';
                    break;
                case 'messages':
                    include 'dashboard/messages.php';
                    break;
                case 'blog':
                    include 'dashboard/blog.php';
                    break;
                case 'projects':
                    include 'dashboard/projects.php';
                    break;
                case 'users':
                    include 'dashboard/users.php';
                    break;
                default:
                    include 'dashboard/overview.php';
                    break;
            }
            ?>
        </div>
    </div>
    
    <script>
        // Logout functionality
        document.getElementById('logout-btn').addEventListener('click', function() {
            // Clear Auth0 session
            localStorage.removeItem('auth0_token');
            localStorage.removeItem('auth0_user');
            
            // Redirect to home page
            window.location.href = '../index.html';
        });
        
        // API request helper function
        async function apiRequest(url, method = 'GET', data = null) {
            const token = localStorage.getItem('auth0_token');
            
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            };
            
            if (data && (method === 'POST' || method === 'PUT')) {
                options.body = JSON.stringify(data);
            }
            
            const response = await fetch(url, options);
            return await response.json();
        }
    </script>
</body>
</html>