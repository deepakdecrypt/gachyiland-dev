<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class LoginController extends Controller
{
    public function login(Request $request)
    {
        // Validate user data (fullname, email, password, etc.)
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|email|max:255', // Change 'users' to your user model table name if different
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation error',
                'statusCode' => 422,
                'errors' => $validator->errors()->toArray(),
            ], 422);
        }

        $username = $request->get('username');
        $password = $request->get('password');

        $clientId = env('AWS_COGNITO_APP_CLIENT_ID');
        $clientSecret = env('AWS_COGNITO_APP_CLIENT_SECRET');
        $userPoolId = env('AWS_COGNITO_USER_POOL_ID');

        // Calculate SECRET_HASH
        $secretHash = $this->generateSecretHash($username, $clientId, $clientSecret);

        $client = new CognitoIdentityProviderClient([
            'region' => env('AWS_REGION'),
            'version' => 'latest'
        ]);

        try {
            $authResult = $client->initiateAuth([
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $secretHash, // Include SECRET_HASH
                ],
                'ClientId' => $clientId,
            ]);

            // Extract access token from the response
            $accessToken = $authResult['AuthenticationResult']['AccessToken'];

            // Handle successful login with access token
            return response()->json([
                'success' => true,
                'statusCode' => 200,
                'message' => 'Login successful',
                'access_token' => $accessToken,
            ]);
        } catch (\Exception $e) {
            // Handle login failure with appropriate error message
            return response()->json([
                'success' => false,
                'statusCode' => 401,
                'error' => $e->getMessage(),
                'message' => 'Invalid credentials or login failed',
            ], 401);
        }
    }

    private function generateSecretHash($username, $clientId, $clientSecret)
    {
        $message = $username . $clientId;
        $hash = hash_hmac('sha256', $message, $clientSecret, true);
        return base64_encode($hash);
    }
}
