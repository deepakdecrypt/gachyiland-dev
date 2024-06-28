<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;
use Aws\Exception\AwsException;

class VerifyOTPController extends Controller
{
    
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function verifyotp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|email|max:255',
            'code' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Username and verification code are required',
                'statusCode' => 422,
                'status' => 422
            ], 422);
        }

        $username = $request->get('username');
        $code = $request->get('code');

        try {

            $clientId = env('AWS_COGNITO_APP_CLIENT_ID');

            $secretHash = $this->cognitoService->generateSecretHash($username);

            $cognitoClient = $this->cognitoService->getCognitoClient();

            $params = [
                'ClientId' => $clientId,
                'Username' => $username,
                'ConfirmationCode' => $code,
                'SecretHash' => $secretHash,
            ];

            $command = $cognitoClient->getCommand('ConfirmSignUp', $params);
            $result = $cognitoClient->execute($command);

            return response()->json([
                'message' => 'Account  verified successfully',
                'status' => true,
                'statusCode' => 200
            ]);
        } catch (AwsException $e) {
            $awsError = $e->getAwsErrorCode();
            if ($awsError === 'UserNotFound') {
                return response()->json([
                    'success' => false,
                    'statusCode' => 401,
                    'message' => 'User not found. Please register',
                ], 401);
            }
            // Handle login failure with appropriate error message
            return response()->json([
                'success' => false,
                'statusCode' => 401,
                'message' => 'Verification code is invalid or expired'
            ], 401);
        }
    }
}
