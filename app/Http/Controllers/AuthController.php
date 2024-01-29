<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Http\Controllers\Carbon;
use App\Http\Controllers\JWTFactory;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    protected function respondWithToken($token)
{
    // Atualiza o tempo de expiração do token
    $expiresAt = Carbon::now()->addMinutes(5)->timestamp;

    // Cria o token
    $customClaims = ['exp' => $expiresAt];
    $payload = JWTFactory::make($customClaims);
    $token = JWTAuth::encode($payload);

    // Faz o dump do token
    var_dump($token);

    return response()->json([
        'access_token' => $token,
        'token_type' => 'bearer',
        'expires_in' => auth()->factory()->getTTL() * 60
    ]);
}
}
