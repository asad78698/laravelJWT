<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\Verification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });


Route::post('/register', [AuthController::class, 'register']);  

Route::post('/login', [AuthController::class, 'login'])->name('login');

Route::middleware('jwt-verify')->group(function(){
    Route::get('/dashboard', [AuthController::class, 'dashboard']);
    Route::get('/logout', [AuthController::class, 'logout']);
});


// Route::get('/email/verify/{id}/{hash}', [Verification::class, 'verify'])->name('verification.verify');
