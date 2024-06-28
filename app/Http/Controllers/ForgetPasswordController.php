<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;
use Aws\Exception\AwsException;

class ForgetPasswordController extends Controller
{
    
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function initiatePasswordReset(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'username' => 'required|string|email|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Username is required',
                'success' => false,
                'statusCode' => 422
            ], 422);
        }

        $username = $request->get('username');

        try {
            $clientId = env('AWS_COGNITO_APP_CLIENT_ID');
            $userPoolId = env('AWS_COGNITO_USER_POOL_ID');

            $secretHash = $this->cognitoService->generateSecretHash($username);

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

            // If the user exists, initiate forgot password
            $forgotPasswordParams = [
                'ClientId' => $clientId,
                'SecretHash' => $secretHash,
                'Username' => $username,
            ];

            $cognitoClient->forgotPassword($forgotPasswordParams);
            return response()->json([
                'message' => 'Password reset initiated. Check your email for the verification code.',
                'success' => true,
                'statusCode' => 200
            ], 200);
        } catch (AwsException $e) {
            return $this->cognitoService->handleResponseError($e);
        }
    }
}
