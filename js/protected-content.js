// Protected Content Handler

// This script manages content that should only be visible to authenticated users
// or users with specific roles/permissions
document.addEventListener('DOMContentLoaded', function() {
    // Initialize protected content areas
    initProtectedContent();
    
    // Listen for authentication state changes
    window.addEventListener('auth-state-changed', function() {
        updateProtectedContent();
    });
});

// Initialize protected content areas
async function initProtectedContent() {
    // Get all elements with the 'protected-content' class
    const protectedElements = document.querySelectorAll('.protected-content');
    
    // Get all elements with role-based protection
    const roleProtectedElements = document.querySelectorAll('[data-required-role]');
    
    // Get all elements with permission-based protection
    const permissionProtectedElements = document.querySelectorAll('[data-required-permission]');
    
    // If there are no protected elements, exit early
    if (protectedElements.length === 0 && 
        roleProtectedElements.length === 0 && 
        permissionProtectedElements.length === 0) return;
    
    // Wait for Auth0 to initialize
    // We'll check every 100ms for up to 5 seconds
    let attempts = 0;
    const maxAttempts = 50;
    
    const checkAuth = setInterval(async function() {
        attempts++;
        
        // If window.auth exists and has the isAuthenticated method
        if (window.auth && typeof window.auth.isAuthenticated === 'function') {
            clearInterval(checkAuth);
            await updateProtectedContent();
        } else if (attempts >= maxAttempts) {
            // If we've tried too many times, give up
            clearInterval(checkAuth);
            console.error('Auth0 initialization timed out');
        }
    }, 100);
}
}

// Update all protected content based on current authentication state
async function updateProtectedContent() {
    try {
        // Check if user is authenticated
        const isAuthenticated = await window.auth.isAuthenticated();
        
        // Update visibility of basic protected elements
        const protectedElements = document.querySelectorAll('.protected-content');
        protectedElements.forEach(element => {
            element.style.display = isAuthenticated ? 'block' : 'none';
        });
        
        // If authenticated, handle role and permission-based content
        if (isAuthenticated) {
            // Update role-based protected elements
            if (window.auth.hasRole) {
                const roleProtectedElements = document.querySelectorAll('[data-required-role]');
                roleProtectedElements.forEach(element => {
                    const requiredRole = element.getAttribute('data-required-role');
                    element.style.display = window.auth.hasRole(requiredRole) ? 'block' : 'none';
                });
            }
            
            // Update permission-based protected elements
            if (window.auth.hasPermission) {
                const permissionProtectedElements = document.querySelectorAll('[data-required-permission]');
                permissionProtectedElements.forEach(element => {
                    const requiredPermission = element.getAttribute('data-required-permission');
                    element.style.display = window.auth.hasPermission(requiredPermission) ? 'block' : 'none';
                });
            }
            
            // Load additional protected data from the server
            await loadProtectedData();
        }
    } catch (error) {
        console.error('Error updating protected content:', error);
    }
}

// Load protected data from the server
async function loadProtectedData() {
    try {
        // Get the access token
        const token = await window.auth.getAccessToken();
        
        if (!token) return;
        
        // Fetch protected content from the server
        const response = await fetch('php/auth.php?endpoint=protected-content', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch protected content');
        }
        
        const data = await response.json();
        
        // Update any elements that should display this protected content
        const protectedContentElements = document.querySelectorAll('[data-protected-content="true"]');
        protectedContentElements.forEach(element => {
            element.textContent = data.content;
        });
        
    } catch (error) {
        console.error('Error loading protected data:', error);
    }
}

// Add a protected content section dynamically
function addProtectedContent(parentElement, content, options = {}) {
    // Create protected content element
    const protectedElement = document.createElement('div');
    protectedElement.className = 'protected-content';
    protectedElement.setAttribute('data-protected-content', 'true');
    
    // Set initial content
    protectedElement.textContent = content || 'Loading protected content...';
    
    // Add role or permission requirements if specified
    if (options.requiredRole) {
        protectedElement.setAttribute('data-required-role', options.requiredRole);
    }
    
    if (options.requiredPermission) {
        protectedElement.setAttribute('data-required-permission', options.requiredPermission);
    }
    
    // Initially hide it
    protectedElement.style.display = 'none';
    
    // Add to parent
    parentElement.appendChild(protectedElement);
    
    // Update its visibility based on current auth state
    updateProtectedElementVisibility(protectedElement);
    
    return protectedElement;
}

// Update visibility of a single protected element
async function updateProtectedElementVisibility(element) {
    try {
        if (!window.auth) return;
        
        const isAuthenticated = await window.auth.isAuthenticated();
        
        // Basic authentication check
        let shouldShow = isAuthenticated;
        
        // Role-based check
        if (shouldShow && element.hasAttribute('data-required-role') && window.auth.hasRole) {
            const requiredRole = element.getAttribute('data-required-role');
            shouldShow = window.auth.hasRole(requiredRole);
        }
        
        // Permission-based check
        if (shouldShow && element.hasAttribute('data-required-permission') && window.auth.hasPermission) {
            const requiredPermission = element.getAttribute('data-required-permission');
            shouldShow = window.auth.hasPermission(requiredPermission);
        }
        
        // Update visibility
        element.style.display = shouldShow ? 'block' : 'none';
        
    } catch (error) {
        console.error('Error updating protected element visibility:', error);
    }

    // Check authentication and update visibility
    if (window.auth && typeof window.auth.isAuthenticated === 'function') {
        window.auth.isAuthenticated().then(isAuthenticated => {
            protectedElement.style.display = isAuthenticated ? 'block' : 'none';
        });
    }
    
    return protectedElement;
}

// Export functions for use in other scripts
window.protectedContent = {
    init: initProtectedContent,
    load: loadProtectedData,
    add: addProtectedContent
};