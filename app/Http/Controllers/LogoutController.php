<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\CognitoService;
use Illuminate\Support\Facades\Log;
use Exception;

class LogoutController extends Controller
{
    /**
     * Handle the logout request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */

    protected $cognitoService;

    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }

    public function logout(Request $request)
    {
        try {
            $authorizationHeader = $request->header('Authorization');
            if (!$authorizationHeader || !preg_match('/Bearer\s(\S+)/', $authorizationHeader, $matches)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Authorization header not found or invalid format',
                    'statusCode' => 400
                ], 400);
            }
            $accessToken = $matches[1];
            
            $cognitoClient = $this->cognitoService->getCognitoClient();

            $cognitoClient->globalSignOut(['AccessToken' => $accessToken ]);
            return response()->json([
                'success' => true,
                'message' => 'Successfully logged out',
                'statusCode' => 200
            ], 200);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to logout, please try again',
                'statusCode' => 500,
                'dsgfdg' => $e->getMessage(),
            ], 500);
        }
    }
}