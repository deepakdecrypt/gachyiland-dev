<?php

namespace Tests\Feature;
use Tests\TestCase;

class RegisterControllerTest extends TestCase
{

    public function test_register_with_invalid_or_empty_request_should_return_error_response()
    {
        $fullname = '';
        $email = '';
        $password = '';
        $response = $this->postJson('/api/v1/register', ['fullname' => $fullname, 'email' => $email, 'password' => $password  ]);
        $response->assertStatus(422)->assertJson(['success' => false,'statusCode' => 422,'message' => "Invalid request error"]);
    }

    public function test_register_user_with_valid_data_should_return_success_response()
    {
        $fullname = env('TEST_CASES_USER_FULLNAME');
        $email = 'testCaseRegister'.rand(1000, 9999).'@gmail.com';
        $password = env('TEST_CASES_PASSWORD_UNVERIFIED');
        $response = $this->postJson('/api/v1/register', ['fullname' => $fullname, 'email' => $email, 'password' => $password  ]);
        $response->assertStatus(200)->assertJson(['success' => true,'statusCode' => 200,'message' => "Registration successful. Please check your email and verify your Email Address.",]);
    }

    public function test_register_user_with_same_email_data_should_return_error_response()
    {
        $fullname = env('TEST_CASES_USER_FULLNAME');
        $email = env('TEST_CASES_USERNAME');
        $password = env('TEST_CASES_PASSWORD_UNVERIFIED');
        $response = $this->postJson('/api/v1/register', ['fullname' => $fullname, 'email' => $email, 'password' => $password  ]);
        $response->assertStatus(409)->assertJson(['success' => false,'statusCode' => 409,'message' => "Email address already exists.",]);
    }

}
