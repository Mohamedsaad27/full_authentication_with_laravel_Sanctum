<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use App\Traits\ApiResponseTrait;
use Illuminate\Support\Facades\DB;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Customs\Services\ResetPasswordService;
use App\Customs\Services\EmailVerificationService;

class AuthController extends Controller
{
    use ApiResponseTrait;
    public function __construct(private EmailVerificationService $service,private ResetPasswordService $resetPasswordService)
    {
        $this->middleware('auth:sanctum')->except(['login','register','resetPassword','sendResetPasswordLink','verifyEmail']);
    }

    public function register(Request $request){
        try{
            $validator = Validator::make($request->all(), [
                'name' => 'required|string',
                'email' => 'required|string|email|unique:users',
                'password' => 'required|string|min:8',
            ]);
            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 422);
            }
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => bcrypt($request->password),
            ]);
            if($user){
                $this->service->sendEmailVerificationLink($user);
                $token = $user->createToken($request->userAgent())->plainTextToken;
                return $this->successResponse(['user' => $user,'token' => $token], 'User created successfully',201);
            }
        }
        catch(\Exception $e){
            return $this->errorResponse(['message' => $e->getMessage()],500);
        }
       
    }
    public function login(Request $request){
        try{
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email',
                'password' => 'required|string|min:8',
            ]);
            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 422);
            }
            if (!Auth::attempt($request->only('email', 'password'))) {
                return $this->errorResponse(['message' => 'Invalid credentials'], 401); 
            }
            $user = Auth::user();
          $token = $user->createToken($request->userAgent())->plainTextToken;
          return $this->successResponse(['user' => $user,'token' => $token]);
        }
        catch(\Exception $e){
            return $this->errorResponse(['message' => $e->getMessage()],500);
        }
    }
    public function logout(Request $request){
        try{
          $user = Auth::user();
          $request->user()->currentAccessToken()->delete();
          return $this->successResponse(['message' => 'Logged out successfully']);
        } catch(\Exception $e){
            return $this->errorResponse(['message' => $e->getMessage()],500);
        }
    }
    public function sendResetPasswordLink(Request $request){
        try{
            $validator = Validator::make($request->all(), [
                'email' => ['required', 'string', 'email', 'exists:users,email']
            ]);
            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 422);
            }
            $user = User::where('email',$request->email)->first();
            if($user){
                $this->resetPasswordService->sendResetPasswordLink($user->email);
                return $this->successResponse(null,'Reset password link sent successfully');
            }
        }catch(\Illuminate\Database\Eloquent\ModelNotFoundException $e){
            return $this->errorResponse('User Not Found',404);
        }
         catch(\Exception $e){
            return $this->errorResponse(['message' => $e->getMessage()],500);
        }
    }
    public function resetPassword(Request $request){
        try {
            $validator = Validator::make($request->all(), [
                'token' => ['required', 'string'],
                'email' => ['required', 'string', 'email', 'exists:users,email'],
                'password' => ['required', 'string', 'min:8', 'confirmed']
            ]);
            if ($validator->fails()) {
                return $this->errorResponse($validator->errors(), 422);
            }
            $user = User::where('email', $request->email)->first();
                $user->password = bcrypt($request->password);
                $user->save();
                return $this->successResponse(null, 'Password reset successfully');  
        } catch (\Exception $e) {
            return $this->errorResponse(['message' => $e->getMessage()], 500);
        }
    }
    public function refreshToken(){
        try {
            $user = Auth::guard('sanctum')->user();
            if (!$user) {
                return $this->errorResponse('Invalid token', 401);
            }
            $user->currentAccessToken()->delete();
            $newToken = $user->createToken('authToken')->plainTextToken;
            return $this->successResponse(['token' => $newToken], 'Token refreshed successfully',201);
        } catch (\Exception $e) {
            return $this->errorResponse(['message' => $e->getMessage()], 500);
        }
    }
    public function verifyEmail(Request $request){
       try{
        $email = $request->query('email');
        $token = $request->query('token');
        $validator = Validator::make(['email' => $email,'token' => $token],
         [
            'email' => ['required', 'string', 'email', 'exists:users,email'],
            'token' => ['required', 'string']
        ]);
        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }
        $user = User::where('email', $email)->first();
         if (!$user) {
            return $this->errorResponse('User not found', 404);
         }
         $storedToken = DB::table('email_verification_tokens')
            ->where('email', $email)
            ->first();

        if (!$storedToken || !Hash::check($token, $storedToken->token)) {
            return $this->errorResponse('Invalid or expired token', 400);
        }
         if (!$user->email_verified_at) {
            $user->email_verified_at = Carbon::now();
            $user->save();
         }
         DB::table('email_verification_tokens')
         ->where('email', $email)
         ->delete();

     return $this->successResponse(null, 'Email verified successfully');
       }catch (\Exception $exception){
            return $this->errorResponse(['message'=>$exception->getMessage()],500);
        }  
    }
    public function profile(Request $request){
        try {
            $user = Auth::user();
            if (!$user){
                return $this->errorResponse('User not found',401);
            }
            return  $this->successResponse(['user' => $user],'messages.user_retrieved_successfully');
        }catch (\Exception $exception){
            return $this->errorResponse(['message'=>$exception->getMessage()],500);
        } 
    }
    public function changePassword(Request $request)
{
    try {
        // Validate request data
        $validator = Validator::make($request->all(), [
            'current_password' => ['required', 'string'],
            'new_password' => ['required', 'string', 'min:8', 'confirmed'], 
        ]);

        if ($validator->fails()) {
            return $this->errorResponse($validator->errors(), 422);
        }

        $user = Auth::user();

        if (!$user || !Hash::check($request->current_password, $user->password)) {
            return $this->errorResponse('Current password is incorrect', 401);
        }

        $user->password = Hash::make($request->new_password);
        $user->save();

        return $this->successResponse(null, 'Password changed successfully');

    } catch (\Exception $e) {
        return $this->errorResponse(['message' => $e->getMessage()], 500);
    }
}
}
