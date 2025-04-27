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

        $user = new User();

        $user->name = $request->name;

        $user->email = $request->email;
        $user->password = FacadesHash::make($request->password);
        $user->save();

        return response()->json([
            'status' => 'success',
            'data' => $user
        ], 200);

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
                'message' => $validator->errors()
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

         

        return response()->json([
            'status' => 'success',
        ], 200)->cookie('token', $token, 60 * 24 * 7); // 7 days

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
