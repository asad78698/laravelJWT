<?php

namespace App\Http\Controllers;

use App\Models\User;
use DB;
use Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash as FacadesHash;
use Illuminate\Support\Facades\Validator as FacadesValidator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\JWT;
use Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {

       try {

        $validator = FacadesValidator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => $validator->errors()->first()
            ], 422);
        }
        $user = new User();

        $user->name = $request->name;

        $user->email = $request->email;
        $user->password = FacadesHash::make($request->password);
        $user->save();

        return response()->json([
            'status' => 'success',
            'message' => 'User has been registered successfully',
            'data' => $user
        ], 200);
       } catch (\Throwable $th) {
        return response()->json([
            'status' => 'error',
            'message' => 'Failed to register user, please try again'
        ], 500);
       }

    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        $validator = FacadesValidator::make($credentials, [
            'email' => 'required|email|exists:users,email',
            'password' => 'required'
        ]); 

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => $validator->errors()->first()
            ], 422);
        }

        $user = User::where('email', $request->email)->first(); 

        if(!$user || !FacadesHash::check($request->password, $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }

        $token = JWTAuth::attempt($credentials);

         

        return response()->json(['message' => 'Login successful'])->cookie(
            'token', $token, 60, '/', null, true, true, false, 'Strict'
        );
    }

    public function dashboard(){
        $user = JWTAuth::user()->name;
        return response()->json([
            'status' => 'success',
            'message' => 'Welcome to the dashboard',
            'user' => $user
        ], 200);
    }
    public function logout(Request $request)
    {
        $token = JWTAuth::getToken();

        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Token not provided'
            ], 400);
        }

        try {

            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json([
                'status' => 'success',
                'message' => 'User has been logged out'
            ], 200);

            //code...
        } catch (JWTException $th) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to logout, please try again'
            ], 500);
        }
    }
}
