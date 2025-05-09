# Enhanced Auth0 Integration

## Features Added

### 1. Persistent Authentication
- Implemented token refresh logic to maintain user sessions across page reloads
- Switched from `sessionStorage` to `localStorage` for persistent authentication state
- Added automatic token refresh handling with error recovery

### 2. Role-Based Access Control (RBAC)
- Added support for user roles and permissions from Auth0
- Implemented `hasRole()` and `hasPermission()` helper functions
- Created data attributes for role-based content protection:
  - `data-required-role="admin"` - Only visible to users with the "admin" role
  - `data-required-permission="read:admin-content"` - Only visible to users with specific permissions

### 3. Enhanced User Profile
- Added role display in the user profile section
- Improved profile UI with better styling
- Added support for displaying user permissions

### 4. Authentication State Management
- Added event-based updates when authentication state changes
- Improved error handling for authentication failures
- Added proper cleanup of authentication data on logout

## How to Use

### Basic Authentication

The basic login/logout functionality remains the same:

```html
<button id="login-btn" class="auth-btn">Login</button>
<button id="logout-btn" class="auth-btn" style="display: none;">Logout</button>
```

### Protected Content

To create content that's only visible to authenticated users:

```html
<div class="protected-content">
    <h3>For Authenticated Users Only</h3>
    <p>This content is only visible when logged in.</p>
</div>
```

### Role-Based Content

To create content that's only visible to users with specific roles:

```html
<div class="protected-content" data-required-role="admin">
    <h3>Admin Content</h3>
    <p>This content is only visible to users with the admin role.</p>
</div>
```

### Permission-Based Content

To create content that's only visible to users with specific permissions:

```html
<div class="protected-content" data-required-permission="read:sensitive-data">
    <h3>Sensitive Data</h3>
    <p>This content requires specific permissions to view.</p>
</div>
```

### Dynamic Protected Content

To add protected content dynamically via JavaScript:

```javascript
// Basic protected content
addProtectedContent(parentElement, "This is protected content");

// Role-based protected content
addProtectedContent(parentElement, "Admin only content", {
    requiredRole: "admin"
});

// Permission-based protected content
addProtectedContent(parentElement, "Special permission content", {
    requiredPermission: "read:special-content"
});
```

## Auth0 Configuration

Make sure your Auth0 application is configured with the following settings:

1. In your Auth0 Dashboard, go to Applications > Your Application
2. Set the following:
   - Allowed Callback URLs: `http://your-domain.com`
   - Allowed Web Origins: `http://your-domain.com`
   - Allowed Logout URLs: `http://your-domain.com`

3. Enable the following in Advanced Settings > Grant Types:
   - Authorization Code
   - Implicit
   - Refresh Token

## Setting Up User Roles in Auth0

1. Go to Auth0 Dashboard > User Management > Roles
2. Create roles like "admin", "editor", etc.
3. Assign users to these roles
4. Make sure your Auth0 Rules are set up to include roles in the ID token

## Auth0 Rule for Including Roles in Tokens

Add this rule in your Auth0 Dashboard > Auth Pipeline > Rules:

```javascript
function (user, context, callback) {
  const namespace = 'https://YOUR_AUTH0_DOMAIN/api/v2/';
  const assignedRoles = (context.authorization || {}).roles || [];

  const idTokenClaims = context.idToken || {};
  const accessTokenClaims = context.accessToken || {};

  idTokenClaims[`${namespace}roles`] = assignedRoles;
  accessTokenClaims[`${namespace}roles`] = assignedRoles;

  callback(null, user, context);
}
```

Replace `YOUR_AUTH0_DOMAIN` with your actual Auth0 domain.

## Troubleshooting

- **Token Refresh Issues**: If users are being logged out unexpectedly, check that refresh tokens are enabled in your Auth0 application settings.
- **Role-Based Content Not Working**: Verify that your Auth0 rule is correctly adding roles to the tokens and that the scope includes 'roles'.
- **Authentication Errors**: Check the browser console for specific error messages related to Auth0 authentication.

## Security Considerations

- Always validate permissions on the server side for any sensitive operations
- Client-side role checks should be used for UI purposes only
- Implement proper API authorization checks using Auth0 scopes and permissions