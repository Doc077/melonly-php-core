<?php

namespace Melonly\Authentication;

use App\Models\User;
use Melonly\Database\Facades\DB;
use Melonly\Encryption\Facades\Hash;
use Melonly\Http\Session;

class Authenticator
{
    public array $userData = [];

    public function login(string $email, string $password): bool
    {
        if ($this->logged()) {
            return false;
        }

        $user = config('database.return_single_record')
            ? DB::query("select * from `users` where `email` = '$email'")
            : DB::query("select * from `users` where `email` = '$email'")[0];

        /**
         * Validate password hash.
         */
        if (Hash::check($password, $user->password)) {
            Session::set('MELONLY_AUTHENTICATED', true);
            Session::set('MELONLY_AUTH_USER_DATA', get_object_vars($user));

            foreach (get_object_vars($user) as $field => $value) {
                $this->userData[$field] = $value;
            }

            return true;
        }

        Session::set('MELONLY_AUTHENTICATED', false);

        return false;
    }

    public function logout(): void
    {
        Session::clear();

        redirect('/login');
    }

    public function logged(): bool
    {
        if (Session::isSet('MELONLY_AUTHENTICATED') && Session::get('MELONLY_AUTHENTICATED') === true) {
            return true;
        }

        return false;
    }

    public function user(): User
    {
        $authUser = new User();

        foreach ($this->userData as $field => $value) {
            $authUser->{$field} = $value;
        }

        return $authUser;
    }

    public function setUserData(array $data): void
    {
        $this->userData = $data;
    }
}
