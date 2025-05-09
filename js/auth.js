// Auth0 Authentication Handler

// Auth0 configuration
const auth0Config = {
    domain: 'YOUR_AUTH0_DOMAIN',  // Replace with your Auth0 domain
    clientId: 'YOUR_AUTH0_CLIENT_ID',  // Replace with your Auth0 client ID
    redirectUri: window.location.origin,  // Redirect to the same origin after login
    audience: 'https://YOUR_AUTH0_DOMAIN/api/v2/',  // Optional: API audience
    responseType: 'token id_token',  // Request both access and ID tokens
    scope: 'openid profile email roles',  // Added roles to requested scopes
    cacheLocation: 'localstorage',  // Store auth data in localStorage for persistence
    useRefreshTokens: true  // Enable refresh tokens for session persistence
};

// Initialize Auth0 client
let auth0Client = null;

// User roles and permissions
let userRoles = [];
let userPermissions = [];

// DOM elements
let loginBtn = null;
let logoutBtn = null;
let profileSection = null;
let userNameElement = null;
let userEmailElement = null;
let userPictureElement = null;
let userRoleElement = null;

// Initialize Auth0 authentication
async function initAuth() {
    // Create Auth0 client
    auth0Client = await createAuth0Client({
        domain: auth0Config.domain,
        client_id: auth0Config.clientId,
        redirect_uri: auth0Config.redirectUri,
        audience: auth0Config.audience,
        responseType: auth0Config.responseType,
        scope: auth0Config.scope
    });

    // Get DOM elements
    loginBtn = document.getElementById('login-btn');
    logoutBtn = document.getElementById('logout-btn');
    profileSection = document.getElementById('user-profile');
    userNameElement = document.getElementById('user-name');
    userEmailElement = document.getElementById('user-email');
    userPictureElement = document.getElementById('user-picture');
    userRoleElement = document.getElementById('user-role');

    // Check for authentication callback
    if (window.location.search.includes('code=')) {
        // Handle the authentication callback
        await auth0Client.handleRedirectCallback();
        // Remove the query parameters
        window.history.replaceState({}, document.title, window.location.pathname);
    }

    // Update UI based on authentication state
    await updateAuthUI();

    // Add event listeners
    if (loginBtn) {
        loginBtn.addEventListener('click', login);
    }
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
}

// Update UI based on authentication state
async function updateAuthUI() {
    // Check if user is authenticated
    const isAuthenticated = await auth0Client.isAuthenticated();

    // Update UI elements based on authentication state
    if (loginBtn) loginBtn.style.display = isAuthenticated ? 'none' : 'inline-block';
    if (logoutBtn) logoutBtn.style.display = isAuthenticated ? 'inline-block' : 'none';
    if (profileSection) profileSection.style.display = isAuthenticated ? 'block' : 'none';

    // If user is authenticated, get user profile and update UI
    if (isAuthenticated) {
        const user = await auth0Client.getUser();
        if (userNameElement) userNameElement.textContent = user.name;
        if (userEmailElement) userEmailElement.textContent = user.email;
        if (userPictureElement && user.picture) {
            userPictureElement.src = user.picture;
            userPictureElement.alt = user.name;
        }
        
        // Extract and store user roles
        if (user[`${auth0Config.audience}roles`]) {
            userRoles = user[`${auth0Config.audience}roles`];
            if (userRoleElement) {
                userRoleElement.textContent = userRoles.join(', ');
            }
        }
        
        // Extract and store user permissions
        if (user[`${auth0Config.audience}permissions`]) {
            userPermissions = user[`${auth0Config.audience}permissions`];
        }

        // Store user info in localStorage for persistence across page reloads
        localStorage.setItem('user', JSON.stringify(user));
        localStorage.setItem('userRoles', JSON.stringify(userRoles));
        localStorage.setItem('userPermissions', JSON.stringify(userPermissions));
        
        // Update protected content based on roles
        updateProtectedContentByRole();
    } else {
        // Clear user info from localStorage
        localStorage.removeItem('user');
        localStorage.removeItem('userRoles');
        localStorage.removeItem('userPermissions');
        userRoles = [];
        userPermissions = [];
    }
}

// Login function
async function login() {
    await auth0Client.loginWithRedirect();
}

// Logout function
async function logout() {
    // Clear session storage
    sessionStorage.removeItem('user');

    // Logout from Auth0
    auth0Client.logout({
        returnTo: window.location.origin
    });
}

// Get access token for API calls with automatic refresh
async function getAccessToken() {
    if (await auth0Client.isAuthenticated()) {
        try {
            // This will automatically refresh the token if needed
            return await auth0Client.getTokenSilently({
                audience: auth0Config.audience,
                scope: auth0Config.scope
            });
        } catch (error) {
            console.error('Error getting access token:', error);
            // If there's an error with the token, try to refresh authentication
            if (error.error === 'login_required') {
                // Token expired and refresh token is invalid, need to re-authenticate
                await login();
            }
            return null;
        }
    }
    return null;
}

// Check if user is authenticated
async function isAuthenticated() {
    return await auth0Client.isAuthenticated();
}

// Get user profile
async function getUserProfile() {
    if (await auth0Client.isAuthenticated()) {
        return await auth0Client.getUser();
    }
    return null;
}

// Initialize Auth0 when DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
    await initAuth();
    // Check for existing authentication
    await checkExistingAuth();
});

// Check if user has a specific role
function hasRole(role) {
    return userRoles.includes(role);
}

// Check if user has a specific permission
function hasPermission(permission) {
    return userPermissions.includes(permission);
}

// Update protected content based on user roles
function updateProtectedContentByRole() {
    // Get all elements with role-based protection
    const roleProtectedElements = document.querySelectorAll('[data-required-role]');
    
    roleProtectedElements.forEach(element => {
        const requiredRole = element.getAttribute('data-required-role');
        if (requiredRole && hasRole(requiredRole)) {
            element.style.display = 'block';
        } else {
            element.style.display = 'none';
        }
    });
    
    // Get all elements with permission-based protection
    const permissionProtectedElements = document.querySelectorAll('[data-required-permission]');
    
    permissionProtectedElements.forEach(element => {
        const requiredPermission = element.getAttribute('data-required-permission');
        if (requiredPermission && hasPermission(requiredPermission)) {
            element.style.display = 'block';
        } else {
            element.style.display = 'none';
        }
    });
}

// Check for existing authentication on page load
async function checkExistingAuth() {
    try {
        // If the user was previously logged in, try to renew tokens automatically
        await auth0Client.getTokenSilently();
        await updateAuthUI();
    } catch (error) {
        // Token expired or not available
        console.log('User needs to log in again');
    }
}

// Export functions for use in other scripts
window.auth = {
    login,
    logout,
    isAuthenticated,
    getUserProfile,
    getAccessToken,
    hasRole,
    hasPermission
};