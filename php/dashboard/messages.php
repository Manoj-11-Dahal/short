<?php
// Get database connection
$conn = getDbConnection();

// Handle actions
$action = isset($_GET['action']) ? $_GET['action'] : 'list';
$messageId = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// View specific message
if ($action === 'view' && $messageId > 0) {
    try {
        // Get message details
        $stmt = $conn->prepare("SELECT * FROM contact_messages WHERE id = :id");
        $stmt->execute([':id' => $messageId]);
        $message = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$message) {
            echo "<p>Message not found.</p>";
            echo "<p><a href='?section=messages'>Back to messages</a></p>";
            exit;
        }
        
        // Mark as read if unread
        if (!$message['is_read']) {
            $updateStmt = $conn->prepare("UPDATE contact_messages SET is_read = TRUE WHERE id = :id");
            $updateStmt->execute([':id' => $messageId]);
        }
        
        // Display message details
        ?>
        <h2>View Message</h2>
        <p><a href="?section=messages">Back to messages</a></p>
        
        <div style="background-color: #f9f9f9; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
            <p><strong>From:</strong> <?php echo htmlspecialchars($message['name']); ?> (<?php echo htmlspecialchars($message['email']); ?>)</p>
            <p><strong>Subject:</strong> <?php echo htmlspecialchars($message['subject']); ?></p>
            <p><strong>Date:</strong> <?php echo date('F j, Y, g:i a', strtotime($message['timestamp'])); ?></p>
            <hr>
            <p><?php echo nl2br(htmlspecialchars($message['message'])); ?></p>
        </div>
        
        <button class="btn-delete" onclick="deleteMessage(<?php echo $message['id']; ?>)">Delete Message</button>
        
        <script>
            // Function to delete a message
            async function deleteMessage(id) {
                if (confirm('Are you sure you want to delete this message?')) {
                    try {
                        const response = await apiRequest(`contact_api.php?action=messages&id=${id}`, 'DELETE');
                        
                        if (response.success) {
                            alert('Message deleted successfully');
                            window.location.href = '?section=messages';
                        } else {
                            alert('Error: ' + response.message);
                        }
                    } catch (error) {
                        alert('Error: ' + error.message);
                    }
                }
            }
        </script>
        <?php
    } catch(PDOException $e) {
        echo "<p>Error: " . $e->getMessage() . "</p>";
    }
} else {
    // List all messages
    try {
        // Get all messages
        $stmt = $conn->prepare("SELECT * FROM contact_messages ORDER BY timestamp DESC");
        $stmt->execute();
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Display messages
        ?>
        <h2>Contact Messages</h2>
        
        <?php if (empty($messages)): ?>
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
                    <?php foreach ($messages as $message): ?>
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
        <?php
    } catch(PDOException $e) {
        echo "<p>Error: " . $e->getMessage() . "</p>";
    }
}
?>