<?php
// Auth0 API Handler for Backend Authentication

// Set headers for JSON responses
header('Content-Type: application/json');

// Auth0 configuration - replace with your actual Auth0 credentials
$auth0Config = [
    'domain' => 'YOUR_AUTH0_DOMAIN',
    'clientId' => 'YOUR_AUTH0_CLIENT_ID',
    'clientSecret' => 'YOUR_AUTH0_CLIENT_SECRET',
    'audience' => 'https://YOUR_AUTH0_DOMAIN/api/v2/',
    'redirectUri' => 'http://localhost/callback',  // Update with your actual callback URL
    'tokenAlgorithm' => 'RS256',                  // JWT signing algorithm
    'tokenLeeway' => 60,                          // Leeway in seconds for JWT exp verification
    'requiredScopes' => ['read:profile', 'write:content'], // Required API scopes
    'mfaEnabled' => true,                         // Enable Multi-factor authentication
];

// Function to validate JWT token
function validateToken($token) {
    global $auth0Config;
    
    // In a production environment, you should use a proper JWT library like firebase/php-jwt
    // This is an enhanced example with better security checks
    
    // Decode token parts
    $tokenParts = explode('.', $token);
    if (count($tokenParts) != 3) {
        error_log("Invalid token format");
        return false;
    }
    
    // Get header and payload
    $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[0])), true);
    $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $tokenParts[1])), true);
    
    if (!$header || !$payload) {
        error_log("Could not decode token parts");
        return false;
    }
    
    // Verify algorithm
    if (!isset($header['alg']) || $header['alg'] !== $auth0Config['tokenAlgorithm']) {
        error_log("Invalid token algorithm");
        return false;
    }
    
    // Check if token is expired with leeway
    $currentTime = time();
    $leeway = $auth0Config['tokenLeeway'] ?? 0;
    
    if (!isset($payload['exp']) || ($payload['exp'] + $leeway) < $currentTime) {
        error_log("Token expired");
        return false;
    }
    
    // Check if token is used before it's valid (nbf = not before)
    if (isset($payload['nbf']) && $payload['nbf'] > ($currentTime + $leeway)) {
        error_log("Token not yet valid");
        return false;
    }
    
    // Check issuer
    if (!isset($payload['iss']) || $payload['iss'] !== 'https://' . $auth0Config['domain'] . '/') {
        error_log("Invalid token issuer");
        return false;
    }
    
    // Check audience
    if (!isset($payload['aud']) || $payload['aud'] !== $auth0Config['clientId']) {
        error_log("Invalid token audience");
        return false;
    }
    
    // Verify required scopes if they exist in the token
    if (isset($payload['scope']) && !empty($auth0Config['requiredScopes'])) {
        $tokenScopes = explode(' ', $payload['scope']);
        foreach ($auth0Config['requiredScopes'] as $requiredScope) {
            if (!in_array($requiredScope, $tokenScopes)) {
                error_log("Missing required scope: $requiredScope");
                return false;
            }
        }
    }
    
    // Check for MFA if enabled
    if ($auth0Config['mfaEnabled'] && (!isset($payload['amr']) || !in_array('mfa', $payload['amr']))) {
        // Only enforce MFA for admin users
        if (isset($payload['role']) && $payload['role'] === 'admin') {
            error_log("MFA required for admin access");
            return false;
        }
    }
    
    return $payload;
}

// Get the authorization header
function getAuthorizationHeader() {
    $headers = null;
    
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER['Authorization']);
    } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    
    return $headers;
}

// Get the bearer token
function getBearerToken() {
    $headers = getAuthorizationHeader();
    
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    
    return null;
}

// Handle API requests
$requestMethod = $_SERVER['REQUEST_METHOD'];
$endpoint = isset($_GET['endpoint']) ? $_GET['endpoint'] : '';

// Protected endpoints require authentication
$protectedEndpoints = ['user-data', 'protected-content'];

// Check if endpoint requires authentication
if (in_array($endpoint, $protectedEndpoints)) {
    $token = getBearerToken();
    
    if (!$token) {
        http_response_code(401);
        echo json_encode(['error' => 'No token provided']);
        exit;
    }
    
    $payload = validateToken($token);
    
    if (!$payload) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid token']);
        exit;
    }
    
    // Token is valid, proceed with the request
    switch ($endpoint) {
        case 'user-data':
            // Return user data from the token
            echo json_encode([
                'success' => true,
                'user' => [
                    'sub' => $payload['sub'],
                    'name' => $payload['name'] ?? '',
                    'email' => $payload['email'] ?? '',
                    'picture' => $payload['picture'] ?? ''
                ]
            ]);
            break;
            
        case 'protected-content':
            // Return protected content
            echo json_encode([
                'success' => true,
                'content' => 'This is protected content only visible to authenticated users.'
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
} else {
    // Public endpoints
    switch ($endpoint) {
        case 'public-data':
            // Return public data
            echo json_encode([
                'success' => true,
                'message' => 'This is public data accessible to anyone.'
            ]);
            break;
            
        default:
            http_response_code(404);
            echo json_encode(['error' => 'Endpoint not found']);
            break;
    }
}