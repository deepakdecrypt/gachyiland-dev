<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;
use Aws\Exception\AwsException;
use Illuminate\Support\Facades\Log;

class ResetPasswordController extends Controller
{
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function resetPassword(Request $request)
    {
        // Validate the request
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|email|max:255',
            'code' => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Invalid input',
                'success' => false,
                'statusCode' => 422
            ], 422);
        }

        $username = $request->get('username');
        $code = $request->get('code');
        $password = $request->get('password');

        try {
            $clientId = env('AWS_COGNITO_APP_CLIENT_ID');

            $userPoolId = env('AWS_COGNITO_USER_POOL_ID');

            // Generate secret hash
            $secretHash = $this->cognitoService->generateSecretHash($username);

            // Get Cognito client
            $cognitoClient = $this->cognitoService->getCognitoClient();

            try {
                $getUserParams = [
                    'UserPoolId' => $userPoolId,
                    'Username' => $username,
                ];

                $cognitoClient->adminGetUser($getUserParams);
            } catch (AwsException $e) {
                return $this->cognitoService->handleResponseError($e);
            }

            // Reset password
            $params = [
                'ClientId' => $clientId,
                'SecretHash' => $secretHash,
                'Username' => $username,
                'ConfirmationCode' => $code,
                'Password' => $password,
            ];

            Log::info('User Reset Password', ['params' => $params]);

            $confirmCommand = $cognitoClient->getCommand('confirmForgotPassword', $params);
            $cognitoClient->execute($confirmCommand);

            return response()->json([
                'message' => 'Password reset successful. You can now log in with your new password.',
                'success' => true,
                'statusCode' => 200,
            ], 200);
            
        } catch (AwsException $e) { 
            return $this->cognitoService->handleResponseError($e);
        }
    }
}
