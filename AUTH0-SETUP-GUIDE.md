# Auth0 Integration Setup Guide

## Overview

This guide will walk you through setting up and using the Auth0 authentication that has been integrated into your portfolio website. Auth0 provides secure authentication and authorization services that allow you to add user login functionality to your application.

## What's Been Implemented

1. **User Authentication**: Login and logout functionality using Auth0
2. **User Profile Display**: A profile section that shows user information after login
3. **Protected Content**: Content that only appears when users are logged in
4. **Backend API Integration**: PHP endpoints for secure data access

## Files Added

- `js/auth.js` - Main Auth0 authentication handler
- `js/protected-content.js` - Manages content visible only to authenticated users
- `css/auth.css` - Styling for authentication elements
- `php/auth.php` - Backend API for protected resources
- `callback.html` - Handles Auth0 authentication redirects
- `README-AUTH0.md` - Detailed documentation

## Setup Instructions

### 1. Create an Auth0 Account and Application

1. Sign up for a free account at [Auth0](https://auth0.com/)
2. Create a new application:
   - Go to **Applications** > **Applications** in the dashboard
   - Click **Create Application**
   - Name it (e.g., "Portfolio Website")
   - Select **Single Page Web Applications**
   - Click **Create**

### 2. Configure Auth0 Settings

1. In your Auth0 application settings, configure:
   - **Allowed Callback URLs**: `http://your-domain/callback.html` (use your actual domain)
   - **Allowed Logout URLs**: `http://your-domain` 
   - **Allowed Web Origins**: `http://your-domain`
   - Click **Save Changes**

### 3. Update Configuration in Your Files

1. Open `js/auth.js` and update:

```javascript
const auth0Config = {
    domain: 'YOUR_AUTH0_DOMAIN',  // e.g., dev-xyz123.us.auth0.com
    clientId: 'YOUR_AUTH0_CLIENT_ID',  // From Auth0 dashboard
    redirectUri: window.location.origin,
    audience: 'https://YOUR_AUTH0_DOMAIN/api/v2/',
    responseType: 'token id_token',
    scope: 'openid profile email'
};
```

2. Open `php/auth.php` and update:

```php
$auth0Config = [
    'domain' => 'YOUR_AUTH0_DOMAIN',
    'clientId' => 'YOUR_AUTH0_CLIENT_ID',
    'clientSecret' => 'YOUR_AUTH0_CLIENT_SECRET',  // From Auth0 dashboard
    'audience' => 'https://YOUR_AUTH0_DOMAIN/api/v2/',
    'redirectUri' => 'http://your-domain/callback.html',
];
```

## How to Use

### Login/Logout

The navigation bar now includes Login and Logout buttons. When a user clicks Login, they'll be redirected to the Auth0 login page. After successful authentication, they'll return to your site and see their profile information.

### Protected Content

Content with the class `protected-content` will only be visible to authenticated users. You can add this class to any element you want to protect:

```html
<div class="protected-content">
    This content is only visible to logged-in users.
</div>
```

### User Profile

The user profile section will automatically display the user's name, email, and profile picture after login.

### Backend API

To access protected API endpoints, use the `getAccessToken()` function:

```javascript
async function fetchProtectedData() {
    const token = await window.auth.getAccessToken();
    const response = await fetch('php/auth.php?endpoint=protected-content', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    const data = await response.json();
    // Use the data
}
```

## Customization

- **Styling**: Modify `css/auth.css` to change the appearance of authentication elements
- **Protected Content**: Add or remove elements with the `protected-content` class
- **User Profile**: Customize the profile display in the `user-profile` section of `index.html`

## Troubleshooting

- **Login Not Working**: Verify your Auth0 domain and client ID are correct
- **Redirect Issues**: Check that your callback URLs are properly configured
- **Console Errors**: Look for JavaScript errors in the browser console

## Security Best Practices

- Never expose your Auth0 client secret in client-side code
- Always validate tokens on the server side
- Use HTTPS in production environments
- Regularly rotate your Auth0 client secret

## Additional Resources

- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 SPA SDK Documentation](https://auth0.github.io/auth0-spa-js/)
- [Auth0 PHP SDK](https://github.com/auth0/auth0-PHP)

For more detailed information, refer to the `README-AUTH0.md` file.