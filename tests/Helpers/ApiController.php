<?php

namespace Devexar\JWTAuth\Tests\Helpers;

use Illuminate\Routing\Controller;

class ApiController extends Controller
{
    public function protected()
    {
        return response()->json(
            [
                'name' => 'David Webb',
                'birthdate' => '4/15/71',
            ]
        );
    }
}
