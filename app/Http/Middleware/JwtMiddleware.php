<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use Exception;
use Illuminate\Support\Facades\Log;

class JwtMiddleware
{
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
                'statusCode' => 400
            ], 400);
        }
        $accessToken = $matches[1];
        try {
            $decodedToken = $this->decodeToken($accessToken);
            Log::info('Token Validated', ['decodedToken' => $decodedToken]);
            // Add decoded token to request attributes for access in controllers
            $request->attributes->add(['decodedToken' => $decodedToken]);
            return $next($request);
        } catch (ExpiredException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token has expired',
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
            Log::info('decodedKeys', ['decodedKeys' => $decodedKeys]);
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
