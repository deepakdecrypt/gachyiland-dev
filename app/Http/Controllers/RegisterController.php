<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;

class RegisterController extends Controller
{
    
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

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

            $signUpResult = $cognitoClient->signUp([
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
                'message' => 'Registration successful. Please check your email and verify your Email Address.',
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

            return response()->json([ 'success' => false, 'statusCode' => $statusCode, 'message' => $message, ], $statusCode);
        }
    }
}
