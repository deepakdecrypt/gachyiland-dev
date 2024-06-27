<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Validator;

class ResendCodeController extends Controller
{
    public function resend(Request $request)
    {
        // Validate incoming request data
        $validator = Validator::make($request->all(), [
            'username' => 'required|string',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'message' => 'Username parameter is required',
                'status' => 400,
                'errors' => $validator->errors()->toArray(),
            ], 400);
        }

        $username = $request->input('username');

        try {
            $clientId = env('AWS_COGNITO_APP_CLIENT_ID');
            $clientSecret = env('AWS_COGNITO_APP_CLIENT_SECRET');
            $userPoolId = env('AWS_COGNITO_USER_POOL_ID');

            $secretHash = $this->generateSecretHash($username, $clientId, $clientSecret);

            $client = new CognitoIdentityProviderClient([
                'region' => env('AWS_REGION'),
                'version' => 'latest',
                'credentials' => [
                    'key' => env('AWS_ACCESS_KEY_ID'),
                    'secret' => env('AWS_SECRET_ACCESS_KEY'),
                ],
            ]);

            // Check if user exists
            try {
                $getUserParams = [
                    'UserPoolId' => $userPoolId,
                    'Username' => $username,
                ];

                $getUserCommand = $client->getCommand('AdminGetUser', $getUserParams);
                $client->execute($getUserCommand);
            } catch (\Exception $e) {
                if ($e->getAwsErrorCode() === 'UserNotFoundException') {
                    return response()->json([
                        'message' => 'User does not exist.',
                        'status' => 404,
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

            $resendCommand = $client->getCommand('ResendConfirmationCode', $resendParams);
            $client->execute($resendCommand);

            return response()->json([
                'message' => 'A new verification code has been sent to your email.',
                'status' => 200,
            ], 200);
        } catch (\Exception $e) {

            return response()->json([
                'message' => 'Failed to resend confirmation code.',
                'error' => $e->getMessage(),
                'status' => 500,
            ], 500);
        }
    }

    private function generateSecretHash($username, $clientId, $clientSecret)
    {
        return base64_encode(hash_hmac('sha256', $username . $clientId, $clientSecret, true));
    }
}
