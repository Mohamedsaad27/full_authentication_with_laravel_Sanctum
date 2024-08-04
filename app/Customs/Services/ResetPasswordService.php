<?php

namespace App\Customs\Services;
use App\Models\EmailVerificationToken;
use App\Notifications\ResetPasswordNotification;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;

class ResetPasswordService {
    public function sendResetPasswordLink(string $email) :void {
        Notification::route('mail', $email)->notify(new ResetPasswordNotification($this->generateResetPasswordLink($email)));
    }
    public function generateResetPasswordLink($email) :string
    {
        $checkIfTokenIfExists = EmailVerificationToken::where('email', $email)->first();
        if ($checkIfTokenIfExists) $checkIfTokenIfExists->delete();

        $token = Str::uuid();
        $url = config('app.url') . "/reset-password?token=" . $token . "&email=" . urlencode($email);

        $saveToken = EmailVerificationToken::create([
            'email' => $email,
            'token' => $token,
            'expired_at' => now()->addHour()
        ]);
        if($saveToken){
            return $url;
        }
        return '';
    }
}
