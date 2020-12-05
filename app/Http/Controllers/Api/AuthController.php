<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
  private $code = 200;

  public function login(Request $request)
  {
    // $validator = Validator::make($request->all(), [
    //   'email'    => $request->input('password'),
    //   'password' => $request->input('password'),
    // ]);

    $auth = Auth::attempt(['email' => request('email'), 'password' => request('password')]);

    if ($auth) 
    {
      $user = Auth::user();
      $token = $user->createToken('nApp')->accessToken;
      $response = [
        'token' => $token,
      ];

      return response()->json($response, 200);
    }
    else
    {
      return response()->json(['errors' => 'unauthorized'], 401);
    }
  }

  public function register(Request $request)
  {
    $validator = Validator::make($request->all(), [
      'name'             => 'required',
      'email'            => 'required|email',
      'password'         => 'required',
      'confirm_password' => 'required|same:password',
    ]);

    if ($validator->fails())
    {
      return response()->json(['errors' => $validator->errors()], 401);
    }

    $data = [
      'name'     => $request->input('name'),
      'email'    => $request->input('email'),
      'password' => bcrypt($request->input('password')),
    ];

    $user = User::create($data);

    $response = [
      'token' => $user->createToken('nApp')->accessToken,
      'name'  => $user->name,
    ];

    return response()->json($response, 200);
  }

  public function detail()
  {
    $user = Auth::user();
    return response()->json(['success' => $user], 200);
  }

  public function logout(Request $request)
  {
    $logout = $request->user()->token()->revoke();
    if($logout)
    {
      return response()->json(['message' => 'Successfully logged out']);
    }
  }
}
