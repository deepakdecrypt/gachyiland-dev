<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;

class RegisterController extends Controller
{
    public function register(Request $request)
    {
        // Validate user data (fullname, email, password, etc.)
        $validator = Validator::make($request->all(), [
            'fullname' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users', // Change 'users' to your user model table name if different
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

        $fullname = $request->get('fullname');
        $email = $request->get('email');
        $password = $request->get('password');

        $client = new CognitoIdentityProviderClient([
            'region' => env('AWS_REGION'),
            'version' => 'latest',
            'credentials' => [
                'key' => env('AWS_ACCESS_KEY_ID'),
                'secret' => env('AWS_SECRET_ACCESS_KEY'),
            ],
        ]);
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

            $secretHash = $this->generateSecretHash($email, env('AWS_COGNITO_APP_CLIENT_ID'), env('AWS_COGNITO_APP_CLIENT_SECRET'));

            $signUpResult = $client->signUp([
                'ClientId' => env('AWS_COGNITO_APP_CLIENT_ID'),
                'SecretHash' => $secretHash,
                'Password' => $password,
                'Username' => $email,
                'UserAttributes' => $userAttributes,
            ]);

            Log::info('User registration signUpResult', ['secretHash' => $secretHash]);

            return response()->json([
                'success' => true,
                'statusCode' => 200,
                'message' => 'Registration successful. Please confirm your email address and set a permanent password in Cognito.',
                'signUpResult' => $signUpResult
            ]);
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

            return response()->json([
                'success' => false,
                'statusCode' => $statusCode,
                'message' => $message,
                'error' => $e->getMessage()
            ], $statusCode);
        }
    }

    private function generateSecretHash($username, $clientId, $clientSecret)
    {
        return base64_encode(hash_hmac('sha256', $username . $clientId, $clientSecret, true));
    }
}
