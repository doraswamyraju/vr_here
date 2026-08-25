import React, { useEffect, useState, useContext } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import { getDashboardRouteForRole } from '../components/GoogleAuthButton';
import { Loader2, AlertCircle, ArrowRight } from 'lucide-react';
import axios from 'axios';

const GoogleCallback = () => {
    const [status, setStatus] = useState('processing');
    const [errorMessage, setErrorMessage] = useState('');
    const location = useLocation();
    const navigate = useNavigate();
    const { googleLogin } = useContext(AuthContext);

    useEffect(() => {
        const processOAuthCallback = async () => {
            try {
                // Check query parameters and hash fragments
                const searchParams = new URLSearchParams(location.search);
                const hashParams = new URLSearchParams(location.hash.replace(/^#/, ''));

                const error = searchParams.get('error') || hashParams.get('error');
                if (error) {
                    throw new Error(searchParams.get('error_description') || `Google returned error: ${error}`);
                }

                const credential = searchParams.get('credential') || hashParams.get('credential') || searchParams.get('id_token') || hashParams.get('id_token');
                const accessToken = searchParams.get('access_token') || hashParams.get('access_token');
                const code = searchParams.get('code');

                let user;

                if (credential || accessToken) {
                    console.log('[GoogleCallback] Found credential/token in URL');
                    user = await googleLogin({ credential, access_token: accessToken });
                } else if (code) {
                    console.log('[GoogleCallback] Found authorization code in URL:', code);
                    const { data } = await axios.post('/api/auth/google', { code });
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('userInfo', JSON.stringify(data));
                    user = data;
                } else {
                    // Check if token was received via postMessage or if no params
                    throw new Error('No authentication credentials found in Google response.');
                }

                console.log('[GoogleCallback] Auth successful for user role:', user?.role);
                setStatus('success');

                const targetUrl = getDashboardRouteForRole(user?.role);
                setTimeout(() => {
                    window.location.href = targetUrl;
                }, 400);
            } catch (err) {
                console.error('[GoogleCallback] Error processing callback:', err);
                setStatus('error');
                setErrorMessage(err.response?.data?.message || err.message || 'Google Sign-In failed');
            }
        };

        processOAuthCallback();
    }, [location]);

    return (
        <div className="min-h-screen bg-slate-900 flex items-center justify-center p-6">
            <div className="max-w-md w-full bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl p-8 text-center text-white shadow-2xl">
                <Link to="/" className="inline-block mb-6">
                    <span className="text-2xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-red-500 to-amber-400">
                        VR HERE
                    </span>
                </Link>

                {status === 'processing' && (
                    <div className="space-y-4">
                        <Loader2 className="w-12 h-12 text-red-500 animate-spin mx-auto" />
                        <h2 className="text-xl font-bold">Authenticating with Google...</h2>
                        <p className="text-slate-300 text-sm">
                            Please wait while we verify your account and prepare your dashboard.
                        </p>
                    </div>
                )}

                {status === 'success' && (
                    <div className="space-y-4">
                        <div className="w-12 h-12 rounded-full bg-green-500/20 text-green-400 flex items-center justify-center mx-auto text-2xl font-bold">
                            ✓
                        </div>
                        <h2 className="text-xl font-bold text-green-400">Authenticated!</h2>
                        <p className="text-slate-300 text-sm">
                            Redirecting to your dashboard...
                        </p>
                    </div>
                )}

                {status === 'error' && (
                    <div className="space-y-4">
                        <AlertCircle className="w-12 h-12 text-red-400 mx-auto" />
                        <h2 className="text-xl font-bold text-red-400">Sign-In Failed</h2>
                        <p className="text-slate-300 text-sm bg-red-950/40 p-3 rounded-lg border border-red-800/40">
                            {errorMessage}
                        </p>
                        <Link
                            to="/login"
                            className="mt-6 inline-flex items-center justify-center w-full py-3 px-4 bg-red-600 hover:bg-red-700 text-white font-semibold rounded-xl transition-all shadow-lg"
                        >
                            <span>Back to Sign In</span>
                            <ArrowRight className="w-4 h-4 ml-2" />
                        </Link>
                    </div>
                )}
            </div>
        </div>
    );
};

export default GoogleCallback;
