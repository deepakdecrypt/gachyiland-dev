<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Exception;

class RefreshTokenController extends Controller
{
    
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function refreshToken(Request $request)
    {

        try {
            $authorizationHeader = $request->header('Authorization');
            if (!$authorizationHeader || !preg_match('/Bearer\s(\S+)/', $authorizationHeader, $matches)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Authorization header not found or invalid format',
                    'statusCode' => 401
                ], 401);
            }
            $refreshToken = $matches[1];
            
            $cognitoClient = $this->cognitoService->getCognitoClient();
            $authResult = $cognitoClient->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'ClientId' => env('AWS_COGNITO_APP_CLIENT_ID'),
                'UserPoolId' => env('AWS_COGNITO_USER_POOL_ID'),
                'AuthParameters' => [
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => env('AWS_COGNITO_APP_CLIENT_SECRET'),
                ]
            ]);

            $auth_results = $authResult['AuthenticationResult'];

            return response()->json([
                'success' => true,
                'message' => 'Access Token generated successfully',
                'statusCode' => 200,
                'auth_results' => $auth_results,
            ], 200);

        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to logout, please try again',
                'statusCode' => 500
            ], 500);
        }

        // Validate user data (fullname, email, password, etc.)
        $validator = Validator::make($request->all(), [
            'fullname' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users', // Change 'users' to your user model table name if different
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid request error',
                'statusCode' => 422,
            ], 422);
        }

        $fullname = $request->get('fullname');
        $email = $request->get('email');
        $password = $request->get('password');

        $cognitoClient = $this->cognitoService->getCognitoClient();
        try {
            $userAttributes = [
                [
                    'Name' => 'name',
                    'Value' => $fullname,
                ],
                [
                    'Name' => 'email',
                    'Value' => $email,
                ]
            ];
            
            $secretHash = $this->cognitoService->generateSecretHash($email);

            $cognitoClient->signUp([
                'ClientId' => env('AWS_COGNITO_APP_CLIENT_ID'),
                'SecretHash' => $secretHash,
                'Password' => $password,
                'Username' => $email,
                'UserAttributes' => $userAttributes,
            ]);

            // Log::info('User registration signUpResult', ['secretHash' => $secretHash]);

            return response()->json([
                'success' => true,
                'statusCode' => 200,
                'message' => 'Registration successful. Please check your email and verify your Email Address.'
            ], 200);

        } catch (\Aws\Exception\AwsException $e) {

            Log::info('Error in User registration', ['errrr' => $e]);
            $message = 'Registration failed.';
            $statusCode = 400;

            if ($e->getAwsErrorCode() === 'UsernameExistsException') {
                $message = 'Email address already exists.';
                $statusCode = 409;
            } elseif ($e->getAwsErrorCode() === 'InvalidPasswordException') {
                $message = 'Password does not meet the requirements.';
                $statusCode = 422;
            } elseif ($e->getAwsErrorCode() === 'InvalidParameterException') {
                $message = 'Invalid parameter.';
                $statusCode = 422;
            } elseif ($e->getAwsErrorCode() === 'CodeDeliveryFailureException') {
                $message = 'Failed to deliver the verification code.';
                $statusCode = 500;
            } elseif ($e->getAwsErrorCode() === 'TooManyRequestsException') {
                $message = 'Too many requests. Please try again later.';
                $statusCode = 429;
            } elseif ($e->getAwsErrorCode() === 'NotAuthorizedException') {
                $message = 'Client is configured with a secret but SECRET_HASH was not received.';
                $statusCode = 401;
            }

            return response()->json([ 'success' => false, 'statusCode' => $statusCode, 'message' => $message, ], $statusCode);
        }
    }
}
