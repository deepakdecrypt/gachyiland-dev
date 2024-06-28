<?php

namespace App\Services;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Exception\AwsException;
use Illuminate\Support\Facades\Log;

class CognitoService
{
    protected $cognitoClient;

    public function __construct()
    {
        $this->cognitoClient = new CognitoIdentityProviderClient([
            'version' => 'latest',
            'region' => env('AWS_REGION'),
            'credentials' => [
                'key' => env('AWS_ACCESS_KEY_ID'),
                'secret' => env('AWS_SECRET_ACCESS_KEY'),
            ],
        ]);
    }
    public function getCognitoClient()
    {
        return $this->cognitoClient;
    }

    public function generateSecretHash($username)
    {
        $clientId = env('AWS_COGNITO_APP_CLIENT_ID');
        $clientSecret = env('AWS_COGNITO_APP_CLIENT_SECRET');
        return base64_encode(hash_hmac('sha256', $username . $clientId, $clientSecret, true));
    }

    public function handleResponseError(AwsException $e)
    {
        $message = $e->getAwsErrorMessage() ?: $e->getMessage();
        $statusCode = $e->getStatusCode() ?: 500;
        Log::error('An error occurred: ' . $e->getMessage());
        return response()->json([
            'success' => false,
            'statusCode' => $statusCode,
            'message' => $message,
        ], $statusCode);
    }
}