<?php

namespace App\Http\Middleware;

use App\Helpers\Utils;
use Closure;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthenticateJWT
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     * @throws JWTException
     */
    public function handle($request, Closure $next)
    {
        // Validating Payload
        if ($payload = JWTAuth::parseToken()->getPayload()) {
            if ($payload->get('ipa') != md5($request->ip())) {
                throw new JWTException(__('api.blocked_device_error', ['reason' => 'origin IP is invalid']), 403);
            }

            if ($payload->get('ura') != md5($request->userAgent())) {
                throw new JWTException(__('api.blocked_device_error', ['reason' => 'origin user agent is invalid']), 403);
            }
          
            if ($payload->get('hst') != md5(gethostname())) {
                throw new JWTException(__('api.blocked_device_error', ['reason' => 'origin hostname is invalid']), 403);
            }
        } else {
            throw new JWTException(__('api.token_error'), 403);
        }
        
        
        // Authenticate
        if (! $user = JWTAuth::parseToken()->authenticate()) {
            throw new JWTException(__('api.token_error'), 403);
        }

        return $next($request);
    }
}
