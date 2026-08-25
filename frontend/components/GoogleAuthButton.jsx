import React, { useContext, useState } from 'react';
import { GoogleOAuthProvider, GoogleLogin } from '@react-oauth/google';
import { AuthContext } from '../context/AuthContext';
import { Loader2 } from 'lucide-react';

const GOOGLE_CLIENT_ID =
    import.meta.env.VITE_GOOGLE_CLIENT_ID ||
    '167766774028-hirpf3e2hkpf1ci1s6oq1koa5dr6p2gd.apps.googleusercontent.com';

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
 * Inner Google Button component
 */
const GoogleAuthButtonInner = ({
    onError,
    onSuccess,
    customRedirectUrl,
    text = 'continue_with',
    width = '100%',
    theme = 'outline',
    size = 'large'
}) => {
    const { googleLogin } = useContext(AuthContext);
    const [isLoading, setIsLoading] = useState(false);

    const handleSuccess = async (credentialResponse) => {
        setIsLoading(true);
        if (onError) onError('');

        try {
            console.log('[GoogleAuthButton] Received credential from Google');
            const user = await googleLogin(credentialResponse);
            console.log('[GoogleAuthButton] Authentication successful, user role:', user?.role);

            if (onSuccess) {
                onSuccess(user);
            }

            const targetUrl = customRedirectUrl || getDashboardRouteForRole(user?.role);
            console.log('[GoogleAuthButton] Redirecting to:', targetUrl);
            window.location.href = targetUrl;
        } catch (err) {
            console.error('[GoogleAuthButton] Authentication failed:', err);
            const errorMessage =
                err.response?.data?.message ||
                err.message ||
                'Google authentication failed. Please try again.';

            if (onError) {
                onError(errorMessage);
            } else {
                alert(errorMessage);
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleError = (error) => {
        console.error('[GoogleAuthButton] Google popup error:', error);
        const msg = 'Google Sign-In was cancelled or failed. Please try again.';
        if (onError) onError(msg);
    };

    return (
        <div className="w-full flex flex-col items-center justify-center">
            {isLoading ? (
                <div className="w-full py-3 px-4 bg-slate-50 border border-slate-200 rounded-xl flex items-center justify-center space-x-2 text-slate-600 font-medium">
                    <Loader2 className="w-5 h-5 animate-spin text-red-600" />
                    <span>Signing in with Google...</span>
                </div>
            ) : (
                <div className="w-full flex justify-center [&>div]:!w-full [&>div>div]:!w-full [&_iframe]:!mx-auto">
                    <GoogleLogin
                        onSuccess={handleSuccess}
                        onError={handleError}
                        theme={theme}
                        size={size}
                        text={text}
                        width={width}
                        shape="rectangular"
                        logo_alignment="center"
                    />
                </div>
            )}
        </div>
    );
};

/**
 * Standalone Google Auth Module
 * Can be imported and used in any page (Login, Register, Modal, Checkout, etc.)
 */
const GoogleAuthButton = (props) => {
    return (
        <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>
            <GoogleAuthButtonInner {...props} />
        </GoogleOAuthProvider>
    );
};

export default GoogleAuthButton;
