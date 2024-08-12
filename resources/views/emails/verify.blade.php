@component('mail::message')
    # Hello!

    Please click the button below to verify your email address.

    @component('mail::button', ['url' => $verificationLink])
        Verify Email
    @endcomponent

    If you did not create an account, no further action is required.

    Thanks,<br>
    {{ config('app.name') }}
@endcomponent
