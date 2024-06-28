<?php

namespace Tests\Feature;
use Tests\TestCase;

class LoginControllerTest extends TestCase
{

    public function test_login_with_invalid_or_empty_request_should_return_error_response()
    {
        $username = '';
        $password = '';
        $response = $this->postJson('/api/v1/login', ['username' => $username, 'password' => $password  ]);
        $response->assertStatus(422)->assertJson(['success' => false,'statusCode' => 422,'message' => "Invalid request error"]);
    }

    public function test_login_with_valid_credentials_should_return_success_response()
    {
        $username = env('TEST_CASES_USERNAME');
        $password = env('TEST_CASES_PASSWORD');
        $response = $this->postJson('/api/v1/login', ['username' => $username, 'password' => $password  ]);
        $response->assertStatus(200)->assertJson(['success' => true,'statusCode' => 200,'message' => "Login successful",]);
    }

    public function test_login_with_unverified_user_should_return_error_response()
    {
        $username = env('TEST_CASES_USERNAME_UNVERIFIED');
        $password = env('TEST_CASES_PASSWORD_UNVERIFIED');
        $response = $this->postJson('/api/v1/login', ['username' => $username, 'password' => $password  ]);
        $response->assertStatus(401)->assertJson(['success' => true,'statusCode' => 204,'message' => "User is not verified. Please verify your email before logging in.",]);
    }

    public function test_login_with_invalid_credentials_should_return_error_response()
    {
        $username = env('TEST_CASES_USERNAME_INVALID');
        $password = env('TEST_CASES_PASSWORD_UNVERIFIED');
        $response = $this->postJson('/api/v1/login', ['username' => $username, 'password' => $password  ]);
        $response->assertStatus(401)->assertJson(['success' => false,'statusCode' => 401,'message' => "Invalid credentials or login failed"]);
    }

}
