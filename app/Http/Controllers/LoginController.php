<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;
use Aws\Exception\AwsException;

class LoginController extends Controller
{
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function login(Request $request)
    {
        // Validate user data (username, password)
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation error',
                'statusCode' => 422
            ], 422);
        }

        $username = $request->get('username');
        $password = $request->get('password');

        $clientId = env('AWS_COGNITO_APP_CLIENT_ID');

        // Calculate SECRET_HASH
        $secretHash = $this->cognitoService->generateSecretHash($username);

        $cognitoClient = $this->cognitoService->getCognitoClient();

        try {
            $authResult = $cognitoClient->initiateAuth([
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $secretHash, // Include SECRET_HASH
                ],
                'ClientId' => $clientId,
            ]);

            $auth_results = $authResult['AuthenticationResult'];

            // Handle successful login with access token
            return response()->json([
                'success' => true,
                'statusCode' => 200,
                'message' => 'Login successful',
                'auth_results' => $auth_results,
            ]);
        } catch (AwsException $e) {
            $awsError = $e->getAwsErrorCode();
            if ($awsError === 'UserNotConfirmedException') {
                return response()->json([
                    'success' => false,
                    'statusCode' => 204,
                    'message' => 'User is not verified. Please verify your email before logging in.',
                ], 401);
            }
            // Handle login failure with appropriate error message
            return response()->json([
                'success' => false,
                'statusCode' => 401,
                'message' => 'Invalid credentials or login failed',
                'error' => $e->getMessage()
            ], 401);
        }
    }
}
