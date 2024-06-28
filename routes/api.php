<?php

use Illuminate\Support\Facades\Route;

Route::post('/login', [\App\Http\Controllers\LoginController::class, 'login']);
Route::post('/register', [\App\Http\Controllers\RegisterController::class, 'register']);
Route::post('/verifyotp', [\App\Http\Controllers\VerifyOTPController::class, 'verifyotp']);
Route::post('/resendcode', [\App\Http\Controllers\ResendCodeController::class, 'resend']);
Route::post('/forgetpassword', [\App\Http\Controllers\ForgetPasswordController::class, 'initiatePasswordReset']);
Route::post('/resetpassword', [\App\Http\Controllers\ResetPasswordController::class, 'resetPassword']);