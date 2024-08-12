<?php


namespace App\Customs\Services;
use App\Mail\VerifyEmail;
use App\Models\EmailVerificationToken;
use App\Notifications\VerifyEmailNotification;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
class EmailVerificationService
{
    public function sendEmailVerificationLink(object $user) :void {
        $email = $user->email;
        $verificationLink = $this->generateVerificationLink($email);

        if ($verificationLink) {
            Mail::to($email)->send(new VerifyEmail($verificationLink));
        }
    }

    public function generateVerificationLink($email) :string
    {
        $checkIfTokenIfExists = EmailVerificationToken::where('email', $email)->first();
        if ($checkIfTokenIfExists) $checkIfTokenIfExists->delete();

        $token = Str::uuid();
        $url = config('app.url') . "/verify-email?token=" . $token . "&email=" . urlencode($email);

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

