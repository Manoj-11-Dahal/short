# Auth0 Integration Guide

This guide will help you set up Auth0 authentication in your portfolio website.

## Prerequisites

1. An Auth0 account (you can sign up for free at [Auth0](https://auth0.com/))
2. Your website running on a web server (local or hosted)

## Setup Instructions

### 1. Create an Auth0 Application

1. Log in to your [Auth0 Dashboard](https://manage.auth0.com/)
2. Go to **Applications** > **Applications** in the left sidebar
3. Click **Create Application**
4. Name your application (e.g., "Portfolio Website")
5. Select **Single Page Web Applications** as the application type
6. Click **Create**

### 2. Configure Auth0 Application Settings

1. In your Auth0 application settings, find the **Allowed Callback URLs**, **Allowed Logout URLs**, and **Allowed Web Origins** fields
2. Add your website's URL to each (e.g., `http://localhost` for local development or your actual domain for production)
3. Scroll down and click **Save Changes**

### 3. Update Configuration in Your Website

1. Open `js/auth.js` and update the Auth0 configuration with your credentials:

```javascript
const auth0Config = {
    domain: 'YOUR_AUTH0_DOMAIN',  // e.g., dev-xyz123.us.auth0.com
    clientId: 'YOUR_AUTH0_CLIENT_ID',  // Found in your Auth0 application settings
    redirectUri: window.location.origin,  // This should match what you set in Auth0 dashboard
    audience: 'https://YOUR_AUTH0_DOMAIN/api/v2/',  // Optional: API audience
    responseType: 'token id_token',
    scope: 'openid profile email'
};
```

2. If you're using the PHP backend authentication, open `php/auth.php` and update the Auth0 configuration:

```php
$auth0Config = [
    'domain' => 'YOUR_AUTH0_DOMAIN',  // e.g., dev-xyz123.us.auth0.com
    'clientId' => 'YOUR_AUTH0_CLIENT_ID',
    'clientSecret' => 'YOUR_AUTH0_CLIENT_SECRET',  // Found in your Auth0 application settings
    'audience' => 'https://YOUR_AUTH0_DOMAIN/api/v2/',
    'redirectUri' => 'http://YOUR_DOMAIN/callback',  // Update with your actual callback URL
];
```

### 4. Test Your Integration

1. Start your web server
2. Navigate to your website
3. Click the "Login" button in the navigation bar
4. You should be redirected to the Auth0 login page
5. After successful login, you should be redirected back to your website with your profile information displayed

## Features Added

- **User Authentication**: Login and logout functionality using Auth0
- **User Profile**: Display of user information after login
- **Protected Content**: Ability to show/hide content based on authentication status
- **Token Handling**: Secure handling of authentication tokens

## Customization

- You can customize the appearance of the login/logout buttons in `css/auth.css`
- Modify the user profile display in the `user-profile` section of `index.html`
- Add additional protected content by checking authentication status with `auth.isAuthenticated()`

## Troubleshooting

- If login doesn't work, check that your Auth0 domain and client ID are correct
- Ensure your callback URLs are properly configured in the Auth0 dashboard
- Check browser console for any JavaScript errors
- For backend issues, check server logs for PHP errors

## Security Considerations

- Never expose your Auth0 client secret in client-side code
- Always validate tokens on the server side before providing access to protected resources
- Use HTTPS in production to secure token transmission

## Additional Resources

- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 SPA SDK Documentation](https://auth0.github.io/auth0-spa-js/)
- [Auth0 PHP SDK](https://github.com/auth0/auth0-PHP) (for more advanced backend integration)