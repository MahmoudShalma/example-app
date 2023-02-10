<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use JWTAuth;
use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;
use Twilio\Rest\Client;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        //Validate data
        $data = $request->only('phone', 'password', 'user_name');
        $validator = Validator::make($data, [
            'phone' => 'required|unique:users',
            'user_name' => 'required',
            'password' => 'required|string|min:6|max:50'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        //Request is valid, create new user
        $user = User::create([
            'phone' => $request->phone,
            'user_name' => $request->user_name,
            'password' => bcrypt($request->password)
        ]);

        $receiverNumber = $user->phone;
        $code = rand(11111, 99999);
        $message = "Your code number is " . $code;

        try {

            $account_sid = getenv("TWILIO_SID");
            $auth_token = getenv("TWILIO_TOKEN");
            $twilio_number = getenv("TWILIO_FROM");

            $client = new Client($account_sid, $auth_token);
            $client->messages->create($receiverNumber, [
                'from' => $twilio_number,
                'body' => $message
            ]);
        } catch (Exception $e) {
            dd("Error: " . $e->getMessage());
        }

        $user->update([
            "code_number" => $code,
        ]);

        //User created, return success response
        return response()->json([
            'success' => true,
            'message' => 'SMS Sent Successfully.',
        ], Response::HTTP_OK);
    }

    public function authenticate(Request $request)
    {
        $credentials = $request->only('phone', 'password');

        //valid credential
        $validator = Validator::make($credentials, [
            'phone' => 'required',
            'password' => 'required|string|min:6|max:50'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        //Request is validated
        //Crean token
        try {
            if (!$token = JWTAuth::attempt($credentials)) {

                return response()->json([
                    'success' => false,
                    'message' => 'Login credentials are invalid.',
                ], 400);
            }
        } catch (JWTException $e) {
            return $credentials;
            return response()->json([
                'success' => false,
                'message' => 'Could not create token.',
            ], 500);
        }

        // return $token;
        //Token created, return with success response and jwt token
        $user = User::where("phone", $request->phone)->first();
        if ($user->active == 1) {
            return response()->json([
                'success' => true,
                'token' => $token,
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'You still need to verify your mobile first',
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        //valid credential
        $validator = Validator::make($request->only('token'), [
            'token' => 'required'
        ]);

        //Send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        //Request is validated, do logout        
        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function get_user(Request $request)
    {
        $this->validate($request, [
            'token' => 'required'
        ]);


        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
    }

    public function active_user(Request $request)
    {

        $data = $request->only('code_number', 'phone');

        $validator = Validator::make($data, [
            'code_number' => 'required',
            'phone' => 'required|exists:users,phone'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->messages()], 200);
        }

        $user = User::where("phone", $request->phone)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'invalid user.',
            ], 400);
        }

        if ($user->code_number == $request->code_number) {
            $user->update([
                "active" => 1,
            ]);
            return response()->json([
                'success' => true,
                'message' => 'Account Active Successfully.',
            ], Response::HTTP_OK);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Wrong Code Number.',
            ], 400);
        }
    }
}
