<?php

namespace Tests\Feature;
use Tests\TestCase;

class ForgetPasswordControllerTest extends TestCase
{

    public function test_forget_password_with_invalid_or_empty_request_should_return_error_response()
    {
        $username = '';
        $response = $this->postJson('/api/v1/forgetpassword', ['username' => $username ]);
        $response->assertStatus(422)->assertJson(['success' => false,'statusCode' => 422,'message' => "Username is required"]);
    }

    public function test_forget_password_with_valid_data_should_return_success_response()
    {
        $username = env('TEST_CASES_USERNAME');
        $response = $this->postJson('/api/v1/forgetpassword', ['username' => $username ]);
        $response->assertStatus(200)->assertJson(['success' => true,'statusCode' => 200,'message' => "Password reset initiated. Check your email for the verification code.",]);
    }

    public function test_forget_password_with_invalid_username_should_return_error_response()
    {
        $username = env('TEST_CASES_USERNAME_INVALID');
        $response = $this->postJson('/api/v1/forgetpassword', ['username' => $username ]);
        $response->assertStatus(400)->assertJson(['success' => false,'statusCode' => 400,'message' => "User does not exist.",]);
    }

}
