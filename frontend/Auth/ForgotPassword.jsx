import axios from 'axios';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            await axios.post('/api/auth/forgotpassword', { email });
            setSubmitted(true);
        } catch (err) {
            setError(err.response?.data?.message || 'Something went wrong. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 flex">
            {/* Left Side - Visual */}
            <div className="hidden lg:flex w-1/2 bg-slate-900 relative overflow-hidden items-center justify-center">
                <div className="absolute inset-0 bg-gradient-to-br from-red-600/20 to-slate-900/40 z-10" />
                <div className="relative z-20 text-center px-12">
                    <h2 className="text-4xl font-bold text-white mb-6">Don't Worry.</h2>
                    <p className="text-slate-300 text-lg leading-relaxed">
                        It happens to the best of us. We'll help you reset your password and get back to business in no time.
                    </p>
                </div>
                {/* Decorative Elements */}
                <div className="absolute top-[-10%] left-[-10%] w-96 h-96 bg-red-600/10 rounded-full blur-3xl" />
                <div className="absolute bottom-[-10%] right-[-10%] w-96 h-96 bg-blue-600/10 rounded-full blur-3xl" />
            </div>

            {/* Right Side - Form */}
            <div className="w-full lg:w-1/2 flex items-center justify-center p-8 bg-white">
                <div className="max-w-md w-full">
                    {submitted ? (
                        <div className="text-center animate-fadeIn">
                            <div className="w-16 h-16 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto mb-6">
                                <CheckCircle className="w-8 h-8" />
                            </div>
                            <h2 className="text-3xl font-bold text-slate-800 mb-4">Check your email</h2>
                            <p className="text-slate-500 mb-8">
                                We've sent a password reset link to <strong>{email}</strong>. Please check your inbox.
                            </p>
                            <Link
                                to="/login"
                                className="inline-flex items-center text-red-600 font-semibold hover:text-red-700 transition-colors"
                            >
                                <ArrowLeft className="w-4 h-4 mr-2" /> Back to Sign In
                            </Link>
                        </div>
                    ) : (
                        <>
                            <div className="mb-10">
                                <Link to="/login" className="inline-flex items-center text-slate-400 hover:text-slate-600 mb-6 transition-colors">
                                    <ArrowLeft className="w-4 h-4 mr-2" /> Back
                                </Link>
                                <h1 className="text-4xl font-bold text-slate-900 mb-3">Forgot Password?</h1>
                                <p className="text-slate-500">Enter your email address to reset your password.</p>
                            </div>

                            {error && (
                                <div className="mb-6 p-4 bg-red-50 text-red-600 text-sm rounded-xl flex items-center shadow-sm border border-red-100">
                                    <span className="mr-3 text-lg">⚠️</span> {error}
                                </div>
                            )}

                            <form onSubmit={handleSubmit} className="space-y-6">
                                <div>
                                    <label className="block text-sm font-medium text-slate-700 mb-2">Email Address</label>
                                    <div className="relative group">
                                        <Mail className="absolute left-4 top-4 h-5 w-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                                        <input
                                            type="email"
                                            value={email}
                                            onChange={(e) => setEmail(e.target.value)}
                                            className="w-full pl-12 pr-4 py-3.5 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-red-100 focus:border-red-500 outline-none transition-all font-medium"
                                            placeholder="name@company.com"
                                            required
                                        />
                                    </div>
                                </div>

                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white font-bold py-4 rounded-xl shadow-lg shadow-red-500/30 transition-all transform hover:-translate-y-0.5 active:translate-y-0 flex items-center justify-center"
                                >
                                    {loading ? <Loader2 className="w-6 h-6 animate-spin" /> : <span className="flex items-center">Reset Password <ArrowRight className="ml-2 w-5 h-5" /></span>}
                                </button>
                            </form>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ForgotPassword;
