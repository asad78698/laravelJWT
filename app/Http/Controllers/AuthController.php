<?php

namespace App\Http\Controllers;

use App\Models\User;
use DB;
use Hash;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {

        $user = new User();

        $user->name = $request->name;
        dd($request->name);

        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();

        $user->sendEmailVerificationNotification();

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'status' => 'success',
            'data' => $user,
            'token' => $token
        ], 200);

    }

    public function login(Request $request)
    {

        $credentials = $request->only('email', 'password');

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid credentials'
            ], 401);
        }


        $user = auth()->user();

        if (!$user->hasVerifiedEmail()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email not verified'
            ], 401);

        }

        return response()->json([
            'status' => 'success',
            'token' => $token
        ], 200);
    }

    public function dashboard()
    {


        $asad = DB::table('users')->where('id', auth()->user()->id)->first();

          

        return response()->json([
            'status' => 'success',
            'data' => $asad,
            'value' => $asad->name
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
