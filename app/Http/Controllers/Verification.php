<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Auth\Events\Verified;
use Illuminate\Http\Request;

class Verification extends Controller
{
    public function verify($id, $hash)
    {
        \Log::info("Verification route hit for user ID: $id");
        $user = User::findOrFail($id);

        if (!hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
            \Log::error("Hash mismatch for user ID: $id");
            return redirect('/')->withErrors(['email' => 'Invalid verification link.']);
        }

        if ($user->hasVerifiedEmail()) {
            \Log::info("User ID $id is already verified.");
            return redirect('/')->with('message', 'Email is already verified.');
        }

        $user->markEmailAsVerified();
        \Log::info("User ID $id marked as verified.");

        event(new Verified($user));

        return redirect('/')->with('message', 'Email successfully verified!');
    }


}
