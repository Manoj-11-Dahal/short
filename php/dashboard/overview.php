<?php
// Get database connection
$conn = getDbConnection();

// Get counts for dashboard overview
try {
    // Count unread messages
    $msgStmt = $conn->prepare("SELECT COUNT(*) as count FROM contact_messages WHERE is_read = FALSE");
    $msgStmt->execute();
    $unreadMessages = $msgStmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Count total messages
    $totalMsgStmt = $conn->prepare("SELECT COUNT(*) as count FROM contact_messages");
    $totalMsgStmt->execute();
    $totalMessages = $totalMsgStmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Count published blog posts
    $blogStmt = $conn->prepare("SELECT COUNT(*) as count FROM blog_posts WHERE status = 'published'");
    $blogStmt->execute();
    $publishedPosts = $blogStmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Count draft blog posts
    $draftStmt = $conn->prepare("SELECT COUNT(*) as count FROM blog_posts WHERE status = 'draft'");
    $draftStmt->execute();
    $draftPosts = $draftStmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Count projects
    $projectStmt = $conn->prepare("SELECT COUNT(*) as count FROM projects");
    $projectStmt->execute();
    $totalProjects = $projectStmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Count users
    $userStmt = $conn->prepare("SELECT COUNT(*) as count FROM users");
    $userStmt->execute();
    $totalUsers = $userStmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // Get recent messages
    $recentMsgStmt = $conn->prepare("SELECT * FROM contact_messages ORDER BY timestamp DESC LIMIT 5");
    $recentMsgStmt->execute();
    $recentMessages = $recentMsgStmt->fetchAll(PDO::FETCH_ASSOC);
} catch(PDOException $e) {
    echo "<p>Error: " . $e->getMessage() . "</p>";
    exit;
}
?>

<h2>Dashboard Overview</h2>

<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px;">
    <div style="background-color: #e3f2fd; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
        <h3>Messages</h3>
        <p style="font-size: 24px; font-weight: bold;"><?php echo $totalMessages; ?></p>
        <p><?php echo $unreadMessages; ?> unread</p>
    </div>
    
    <div style="background-color: #e8f5e9; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
        <h3>Blog Posts</h3>
        <p style="font-size: 24px; font-weight: bold;"><?php echo $publishedPosts + $draftPosts; ?></p>
        <p><?php echo $publishedPosts; ?> published, <?php echo $draftPosts; ?> drafts</p>
    </div>
    
    <div style="background-color: #fff8e1; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
        <h3>Projects</h3>
        <p style="font-size: 24px; font-weight: bold;"><?php echo $totalProjects; ?></p>
    </div>
    
    <div style="background-color: #f3e5f5; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
        <h3>Users</h3>
        <p style="font-size: 24px; font-weight: bold;"><?php echo $totalUsers; ?></p>
    </div>
</div>

<h3>Recent Messages</h3>

<?php if (empty($recentMessages)): ?>
    <p>No messages found.</p>
<?php else: ?>
    <table class="dashboard-table">
        <thead>
            <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Subject</th>
                <th>Date</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($recentMessages as $message): ?>
                <tr>
                    <td><?php echo htmlspecialchars($message['name']); ?></td>
                    <td><?php echo htmlspecialchars($message['email']); ?></td>
                    <td><?php echo htmlspecialchars($message['subject']); ?></td>
                    <td><?php echo date('M d, Y', strtotime($message['timestamp'])); ?></td>
                    <td>
                        <?php if ($message['is_read']): ?>
                            <span class="badge badge-success">Read</span>
                        <?php else: ?>
                            <span class="badge badge-warning">Unread</span>
                        <?php endif; ?>
                    </td>
                    <td class="action-buttons">
                        <a href="?section=messages&action=view&id=<?php echo $message['id']; ?>" class="btn-view">View</a>
                        <button class="btn-delete" onclick="deleteMessage(<?php echo $message['id']; ?>)">Delete</button>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    
    <script>
        // Function to delete a message
        async function deleteMessage(id) {
            if (confirm('Are you sure you want to delete this message?')) {
                try {
                    const response = await apiRequest(`contact_api.php?action=messages&id=${id}`, 'DELETE');
                    
                    if (response.success) {
                        alert('Message deleted successfully');
                        window.location.reload();
                    } else {
                        alert('Error: ' + response.message);
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            }
        }
    </script>
<?php endif; ?>