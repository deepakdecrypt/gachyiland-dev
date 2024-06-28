<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Aws\Exception\AwsException;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Validator;

class ResendCodeController extends Controller
{
    
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function resend(Request $request)
    {
        // Validate incoming request data
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|email|max:255',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Username is required',
                'success' => false,
                'statusCode' => 422,
            ], 422);
        }

        $username = $request->get('username');

        try {
            $clientId = env('AWS_COGNITO_APP_CLIENT_ID');
            $userPoolId = env('AWS_COGNITO_USER_POOL_ID');

            $secretHash = $this->cognitoService->generateSecretHash($username);

            $cognitoClient = $this->cognitoService->getCognitoClient();

            // Check if user exists
            try {
                $getUserParams = [
                    'UserPoolId' => $userPoolId,
                    'Username' => $username,
                ];

                $getUserCommand = $cognitoClient->getCommand('AdminGetUser', $getUserParams);
                $cognitoClient->execute($getUserCommand);
            } catch (AwsException $e) {
                if ($e->getAwsErrorCode() === 'UserNotFoundException') {
                    return response()->json([
                        'message' => 'User does not exist.',
                        'success' => false,
                        'statusCode' => 404,
                    ], 404);
                } else {
                    throw $e;
                }
            }

            // Resend confirmation code
            $resendParams = [
                'ClientId' => $clientId,
                'SecretHash' => $secretHash,
                'Username' => $username,
            ];

            $resendCommand = $cognitoClient->getCommand('ResendConfirmationCode', $resendParams);
            $cognitoClient->execute($resendCommand);

            return response()->json([
                'message' => 'A new verification code has been sent to your email.',
                'success' => true,
                'statusCode' => 200,
            ], 200);
        } catch (\Exception $e) {

            return response()->json([
                'message' => 'Failed to resend confirmation code.',
                'error' => $e->getMessage(),
                'success' => false,
                'statusCode' => 500,
            ], 500);
        }
    }
}
