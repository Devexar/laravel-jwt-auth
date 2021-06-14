<?php

return [
    'guard' => [
        // Show a JSON response when the token is invalid, stating the reason.
        'show_error_reason' => false,
    ],

    'jwt' => [
        'aud_config_override' => [
            // You can specify config override by different 'aud' (Audience) claims. Any config param can be overridden.
            // This is useful, for example if you have a mobile app and a desktop app, since usually you want your
            // mobile users to remain logged in.
            'users' => [
                'ttl' => [
                    'on_create' => env('JWT_TTL_CREATE', 604800), // 7 days
                    'on_refresh' => env('JWT_TTL_REFRESH', 604800),
                ]
            ]
        ],

        // Secret key to encode the tokens.
        // Will not be used if 'keys' are set.
        'secret' => env('JWT_SECRET'),

        // Keys
        // Path to a key file, public and private. Must be in PEM format.
        'keys' => [
            'public' => env('JWT_PUBLIC_KEY'),
            'private' => env('JWT_PRIVATE_KEY'),
        ],

        // Time to live
        // How many seconds from the creation or refresh the token will be valid for.
        // Set 'on_create' to 0 to not add the 'exp' claim to the token. Tokens with 'exp' = 0 will not be refreshed.
        // Set 'on_refresh' to control the 'exp' claim value in a token when it is refreshed.
        'ttl' => [
            'on_create' => env('JWT_TTL_CREATE', 60),
            'on_refresh' => env('JWT_TTL_REFRESH', 60),
        ],

        // Algorithm to use.
        // See https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40 for a list of spec-compliant
        // algorithms.
        'algorithm' => env('JWT_ALGORITHM', 'HS256'),

        // Add the 'grd' custom claim to identify the Guard that generates the token.
        // The grd claim identifies the guard name in your Laravel config. This is needed in case you declare multiple
        // guards, with different user providers, so the Guard that didn't generate the token will not try to handle it,
        // as it might have a different user provider.
        // If you turn this off, also remove 'grd' from the required claims.
        'add_guard_claim' => true,

        // A token will be invalid if missing one of the following claims.
        'required_claims' => [
            'iss', // Issuer
            'iat', // Issued at
            'exp', // Expire time
            'nbf', // Not before
            'sub', // Subject
            'grd', // Guard ID (custom).
        ],

        'leeway' => env('JWT_LEEWAY', 0),

        'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

        'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', 0),
    ]


];
