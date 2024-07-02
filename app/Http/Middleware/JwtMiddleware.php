<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use Exception;
use Illuminate\Support\Facades\Log;
use App\Services\CognitoService;
use Aws\Exception\AwsException;

class JwtMiddleware
{
    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $authorizationHeader = $request->header('Authorization');
        if (!$authorizationHeader || !preg_match('/Bearer\s(\S+)/', $authorizationHeader, $matches)) {
            return response()->json([
                'success' => false,
                'message' => 'Authorization header not found or invalid format',
                'statusCode' => 401
            ], 401);
        }
        $accessToken = $matches[1];
        try {
            $decodedToken = $this->decodeToken($accessToken);
            $cognitoClient = $this->cognitoService->getCognitoClient();
            $userData = $cognitoClient->getUser(['AccessToken' => $accessToken ]);
            $request->attributes->add(['decodedToken' => $decodedToken, 'userData' => $userData]);
            return $next($request);
        } catch (ExpiredException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token has expired',
                'statusCode' => 401
            ], 401);
        } catch (AwsException $e) {
            if ($e->getAwsErrorCode() == 'NotAuthorizedException') {
                return response()->json([
                    'success' => false,
                    'message' => 'Access Token has been revoked',
                    'statusCode' => 401
                ], 401);
            }
            Log::error('AWS error: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'Token is invalid',
                'statusCode' => 401
            ], 401);
        } catch (Exception $e) {
            Log::error('JWT token verification failed: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'message' => 'Token is invalid',
                'statusCode' => 401
            ], 401);
        }
    }

    private function decodeToken($token)
    {
        $region = env('AWS_REGION');
        $userPoolId = env('AWS_COGNITO_USER_POOL_ID');
        $cognitoKeysUrl = "https://cognito-idp.{$region}.amazonaws.com/{$userPoolId}/.well-known/jwks.json";   
        $keys = @file_get_contents($cognitoKeysUrl);
        if ($keys === false) {
            throw new Exception('Unable to fetch Cognito keys');
        }
        $decodedKeys = json_decode($keys, true);
        if (!isset($decodedKeys['keys'])) {
            throw new Exception('Invalid JWK set format');
        }
        // Verify the token signature
        try {
            $decodedToken = JWT::decode($token, JWK::parseKeySet(['keys' => $decodedKeys['keys'] ], 'RS256'));
        } catch (ExpiredException $e) {
            throw $e; // Handle expiration separately if needed
        } catch (Exception $e) {
            Log::error('JWT token verification failed: ' . $e->getMessage());
            throw new Exception('Token verification failed');
        }
        return $decodedToken;
    }

}
