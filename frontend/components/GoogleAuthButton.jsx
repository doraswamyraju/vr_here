import React, { useState } from 'react';
import { Loader2 } from 'lucide-react';

const GOOGLE_CLIENT_ID =
    import.meta.env.VITE_GOOGLE_CLIENT_ID ||
    '167766774028-lrhfc69ubgv0po3kp9gup09cfvd82jlu.apps.googleusercontent.com';

/**
 * Role-to-Dashboard route mapper
 */
export const getDashboardRouteForRole = (role) => {
    switch (role?.toLowerCase()) {
        case 'admin':
            return '/admin';
        case 'employee':
            return '/employee';
        case 'partner':
            return '/partner-dashboard';
        case 'freelancer':
            return '/freelancer-dashboard';
        case 'client':
        case 'customer':
        default:
            return '/customer-dashboard';
    }
};

/**
 * Standalone Google Auth Module
 * Beautiful, modern, and high-converting Google Sign-In button
 */
const GoogleAuthButton = ({
    text = 'Continue with Google',
    className = ''
}) => {
    const [isLoading, setIsLoading] = useState(false);

    const handleGoogleRedirect = () => {
        setIsLoading(true);
        const origin = window.location.origin;
        const redirectUri = `${origin}/auth/google/callback`;

        const authParams = new URLSearchParams({
            client_id: GOOGLE_CLIENT_ID,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: 'openid email profile',
            access_type: 'offline',
            prompt: 'select_account'
        });

        const targetUrl = `https://accounts.google.com/o/oauth2/v2/auth?${authParams.toString()}`;
        console.log('[GoogleAuthButton] Redirecting to Google OAuth:', targetUrl);
        window.location.href = targetUrl;
    };

    return (
        <button
            type="button"
            onClick={handleGoogleRedirect}
            disabled={isLoading}
            className={`w-full relative overflow-hidden group bg-white hover:bg-slate-50/90 text-slate-800 font-semibold py-3.5 px-6 rounded-xl border border-slate-200 hover:border-slate-300 shadow-[0_2px_8px_-2px_rgba(0,0,0,0.06),0_1px_3px_-1px_rgba(0,0,0,0.08)] hover:shadow-[0_6px_16px_-3px_rgba(0,0,0,0.1),0_2px_6px_-2px_rgba(0,0,0,0.06)] transition-all duration-200 transform hover:-translate-y-0.5 active:translate-y-0 active:scale-[0.99] flex items-center justify-center space-x-3 cursor-pointer ${className}`}
        >
            {/* Subtle light shimmer effect on hover */}
            <div className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-1000 bg-gradient-to-r from-transparent via-white/40 to-transparent pointer-events-none" />

            {isLoading ? (
                <div className="flex items-center space-x-2.5">
                    <Loader2 className="w-5 h-5 animate-spin text-red-600" />
                    <span className="text-slate-600 text-[15px] font-medium tracking-wide">
                        Connecting to Google...
                    </span>
                </div>
            ) : (
                <>
                    {/* Google Official Multicolored Logo */}
                    <div className="w-5 h-5 flex-shrink-0 flex items-center justify-center transition-transform group-hover:scale-110 duration-200">
                        <svg className="w-full h-full" viewBox="0 0 24 24">
                            <path
                                fill="#4285F4"
                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                            />
                            <path
                                fill="#34A853"
                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                            />
                            <path
                                fill="#FBBC05"
                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                            />
                            <path
                                fill="#EA4335"
                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                            />
                        </svg>
                    </div>
                    <span className="text-slate-800 font-semibold text-[15px] tracking-tight group-hover:text-slate-900 transition-colors">
                        {text}
                    </span>
                </>
            )}
        </button>
    );
};

export default GoogleAuthButton;
