<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;

class VerifyOTPController extends Controller
{
    public function verifyotp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'code' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => 'Email and verification code are required',
                'status' => 422,
                'errors' => $validator->errors()->toArray(),
            ], 422);
        }

        $email = $request->input('email');
        $code = $request->input('code');

        try {
            $clientId = env('AWS_COGNITO_APP_CLIENT_ID');
            $clientSecret = env('AWS_COGNITO_APP_CLIENT_SECRET');

            $secretHash = $this->generateSecretHash($email, $clientId, $clientSecret);

            $client = new CognitoIdentityProviderClient([
                'region' => env('AWS_REGION'),
                'version' => 'latest',
                'credentials' => [
                    'key' => env('AWS_ACCESS_KEY_ID'),
                    'secret' => env('AWS_SECRET_ACCESS_KEY'),
                ],
            ]);

            $params = [
                'ClientId' => $clientId,
                'Username' => $email,
                'ConfirmationCode' => $code,
                'SecretHash' => $secretHash,
            ];

            $command = $client->getCommand('ConfirmSignUp', $params);
            $result = $client->execute($command);

            return response()->json([
                'message' => 'Email verified successfully',
                'status' => 200,
                'result' => $result,
            ]);
        } catch (\Exception $e) {
            Log::info('Error verifying email:', ['message ' => $e->getMessage()]);

            return response()->json([
                'message' => 'Failed to verify email',
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
