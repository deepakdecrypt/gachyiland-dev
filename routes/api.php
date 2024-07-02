<?php

use Illuminate\Support\Facades\Route;
use App\Http\Middleware\JwtMiddleware;
use App\Http\Controllers\LoginController;
use App\Http\Controllers\RegisterController;
use App\Http\Controllers\VerifyOTPController;
use App\Http\Controllers\ResendCodeController;
use App\Http\Controllers\ForgetPasswordController;
use App\Http\Controllers\ResetPasswordController;
use App\Http\Controllers\LogoutController;
use App\Http\Controllers\RefreshTokenController;

Route::post('/login', [LoginController::class, 'login']);
Route::post('/register', [RegisterController::class, 'register']);
Route::post('/verifyotp', [VerifyOTPController::class, 'verifyotp']);
Route::post('/resendcode', [ResendCodeController::class, 'resend']);
Route::post('/forgetpassword', [ForgetPasswordController::class, 'initiatePasswordReset']);
Route::post('/resetpassword', [ResetPasswordController::class, 'resetPassword']);
Route::get('/refreshtoken', [RefreshTokenController::class, 'refreshToken']);

Route::middleware([JwtMiddleware::class])->group(function () {
    Route::get('/logout', [LogoutController::class, 'logout']);
});