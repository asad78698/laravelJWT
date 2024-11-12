<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class JWT
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {

        try {
            //this will check if the user is authenticated or not

            $user = JWTAuth::parseToken()->authenticate();

        } catch (Exception $e) {

            //exception se token invalid or expiration ka pata chale ga 

            if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenInvalidException) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token is Invalid'
                ], 401);

            } else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenExpiredException) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token is Expired'
                ], 401);

            } else if ($e instanceof \Tymon\JWTAuth\Exceptions\TokenBlacklistedException) {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Token is Blacklisted'
                ], 401);
            } else {
                return response()->json([
                    'status' => 'error',
                    'message' => 'Authorization Token not found'
                ], 401);
            }
        }
        return $next($request);
    }
}
