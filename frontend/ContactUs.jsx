import React, { useState, useEffect } from 'react';
import {
    Phone, Mail, MapPin, Clock, ArrowRight, CheckCircle2,
    Send, Loader2, MessageSquare, ChevronDown, Menu, X
} from 'lucide-react';

const ContactUsPage = () => {
    // --- STATE ---
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [formData, setFormData] = useState({
        name: '',
        phone: '',
        email: '',
        service: '',
        message: ''
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [submitted, setSubmitted] = useState(false);

    // --- EFFECT: READ URL PARAMS ---
    useEffect(() => {
        // Basic query param parsing
        const params = new URLSearchParams(window.location.search);
        const serviceParam = params.get('service');
        if (serviceParam) {
            setFormData(prev => ({ ...prev, service: serviceParam }));
        }
    }, []);

    // --- ACTIONS ---
    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        // Simulate API call
        setTimeout(() => {
            setIsSubmitting(false);
            setSubmitted(true);
            // Reset after showing success
            setTimeout(() => setSubmitted(false), 5000);
            setFormData({ name: '', phone: '', email: '', service: '', message: '' });
        }, 1500);
    };

    // --- COMPONENTS ---
    const Header = () => (
        <>
            <div className="bg-slate-900 text-slate-400 text-xs py-2 px-4 hidden lg:block border-b border-slate-800">
                <div className="max-w-[1400px] mx-auto flex justify-between items-center">
                    <div className="flex space-x-6">
                        <span className="flex items-center"><MapPin className="w-3 h-3 mr-2 text-red-600" /> Hyderabad, India</span>
                        <span className="flex items-center"><Clock className="w-3 h-3 mr-2 text-red-600" /> Mon - Sat: 10AM - 7PM</span>
                    </div>
                    <div className="flex items-center space-x-6">
                        <a href="mailto:vrherebms@gmail.com" className="flex items-center hover:text-red-500 transition"><Mail className="w-3 h-3 mr-2" /> vrherebms@gmail.com</a>
                        <a href="tel:+918008530606" className="flex items-center hover:text-red-500 font-bold transition"><Phone className="w-3 h-3 mr-2" /> +91 80085 30606</a>
                    </div>
                </div>
            </div>

            <header className="sticky top-0 z-50 bg-white border-b border-slate-100 py-4 shadow-sm">
                <div className="max-w-[1400px] mx-auto px-4 sm:px-6">
                    <div className="flex justify-between items-center">
                        {/* LOGO LINK */}
                        <a href="/" className="flex items-center flex-shrink-0 group cursor-pointer">
                            <div className="w-10 h-10 bg-black rounded-lg flex items-center justify-center mr-3 shadow-lg group-hover:bg-red-600 transition duration-300 relative overflow-hidden transform group-hover:scale-105">
                                <div className="absolute inset-0 bg-white/20 translate-y-full group-hover:translate-y-0 transition duration-300"></div>
                                <span className="text-white font-black text-xl tracking-tighter">VR</span>
                            </div>
                            <div className="flex flex-col">
                                <span className="text-2xl font-extrabold text-black leading-none tracking-tight group-hover:text-red-600 transition-colors">VR HERE</span>
                                <span className="text-[10px] font-bold text-red-600 uppercase tracking-widest mt-0.5">Business Solutions</span>
                            </div>
                        </a>

                        <nav className="hidden lg:flex items-center space-x-2">
                            <a href="/" className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 rounded-full hover:bg-red-50 transition-all">Home</a>
                            <a href="/pvt-ltd-registration" className="px-4 py-2 text-sm font-bold text-slate-700 hover:text-red-600 rounded-full hover:bg-red-50 transition-all">Services</a>
                        </nav>

                        <button className="lg:hidden p-2 text-slate-800 hover:bg-slate-100 rounded-lg transition" onClick={() => setIsMobileMenuOpen(true)}>
                            <Menu className="w-7 h-7" />
                        </button>
                    </div>
                </div>
            </header>

            {/* MOBILE MENU */}
            <div className={`fixed inset-0 bg-white z-[60] transform transition-transform duration-300 lg:hidden overflow-y-auto ${isMobileMenuOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                <div className="p-4 border-b border-slate-100 flex justify-between items-center sticky top-0 bg-white z-10">
                    <div className="flex items-center">
                        <span className="font-bold text-lg">Menu</span>
                    </div>
                    <button onClick={() => setIsMobileMenuOpen(false)} className="p-2 bg-slate-100 rounded-full hover:bg-red-100 hover:text-red-600 transition"><X className="w-6 h-6" /></button>
                </div>
                <div className="p-4 space-y-4">
                    <a href="/" className="block text-lg font-bold">Home</a>
                    <a href="/pvt-ltd-registration" className="block text-lg font-bold">Services</a>
                </div>
            </div>
        </>
    );

    const Footer = () => (
        <footer className="bg-[#0f172a] text-slate-300 pt-12 pb-8 border-t border-slate-800 font-sans mt-auto">
            <div className="max-w-[1400px] mx-auto px-4 text-center">
                <p className="text-sm text-slate-500">&copy; {new Date().getFullYear()} VR HERE Business Management Solutions. All rights reserved.</p>
            </div>
        </footer>
    );

    return (
        <div className="font-sans text-slate-800 bg-slate-50 min-h-screen flex flex-col">
            <Header />

            <main className="flex-grow">
                <div className="relative bg-slate-900 py-20 text-center overflow-hidden">
                    <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-10"></div>
                    <div className="relative z-10 max-w-2xl mx-auto px-4">
                        <h1 className="text-4xl lg:text-5xl font-black text-white mb-6">Contact Us</h1>
                        <p className="text-lg text-slate-400">Have a question or need a specific service? We're here to help.</p>
                    </div>
                </div>

                <div className="max-w-7xl mx-auto px-4 -mt-10 relative z-20 pb-20">
                    <div className="grid lg:grid-cols-3 gap-8">

                        {/* LEFT: Contact Info */}
                        <div className="bg-white rounded-2xl p-8 shadow-xl border border-slate-100 h-fit">
                            <h3 className="text-xl font-bold text-slate-900 mb-6">Get in Touch</h3>
                            <div className="space-y-6">
                                <div className="flex items-start">
                                    <div className="p-3 bg-red-50 text-red-600 rounded-lg mr-4">
                                        <MapPin className="w-6 h-6" />
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-slate-900">Office Address</h4>
                                        <p className="text-sm text-slate-500 mt-1 leading-relaxed">
                                            #31, Dwarawati, Subodaya Colony,<br />
                                            Kukatpally, Hyderabad - 500072<br />
                                            Telangana, India
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="p-3 bg-red-50 text-red-600 rounded-lg mr-4">
                                        <Phone className="w-6 h-6" />
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-slate-900">Phone</h4>
                                        <a href="tel:+918008530606" className="text-sm text-slate-500 mt-1 block hover:text-red-600 transition">+91 80085 30606</a>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="p-3 bg-red-50 text-red-600 rounded-lg mr-4">
                                        <Mail className="w-6 h-6" />
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-slate-900">Email</h4>
                                        <a href="mailto:vrherebms@gmail.com" className="text-sm text-slate-500 mt-1 block hover:text-red-600 transition">vrherebms@gmail.com</a>
                                    </div>
                                </div>
                            </div>
                        </div>

                        {/* RIGHT: Contact Form */}
                        <div className="lg:col-span-2 bg-white rounded-2xl p-8 shadow-xl border border-slate-100">
                            <h3 className="text-xl font-bold text-slate-900 mb-6">Send Message</h3>

                            {submitted ? (
                                <div className="bg-green-50 border border-green-200 rounded-xl p-8 text-center animate-fade-in">
                                    <div className="w-16 h-16 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto mb-4">
                                        <CheckCircle2 className="w-8 h-8" />
                                    </div>
                                    <h4 className="text-xl font-bold text-green-800 mb-2">Message Sent!</h4>
                                    <p className="text-green-700">Thank you for contacting us. Our team will get back to you shortly.</p>
                                </div>
                            ) : (
                                <form onSubmit={handleSubmit} className="space-y-6">
                                    <div className="grid md:grid-cols-2 gap-6">
                                        <div className="space-y-2">
                                            <label className="text-sm font-bold text-slate-700">Full Name</label>
                                            <input required name="name" value={formData.name} onChange={handleChange} type="text" className="w-full px-4 py-3 rounded-lg border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-200 outline-none transition" placeholder="John Doe" />
                                        </div>
                                        <div className="space-y-2">
                                            <label className="text-sm font-bold text-slate-700">Mobile Number</label>
                                            <input required name="phone" value={formData.phone} onChange={handleChange} type="tel" className="w-full px-4 py-3 rounded-lg border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-200 outline-none transition" placeholder="+91 98765 43210" />
                                        </div>
                                    </div>

                                    <div className="space-y-2">
                                        <label className="text-sm font-bold text-slate-700">Email Address</label>
                                        <input required name="email" value={formData.email} onChange={handleChange} type="email" className="w-full px-4 py-3 rounded-lg border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-200 outline-none transition" placeholder="john@company.com" />
                                    </div>

                                    <div className="space-y-2">
                                        <label className="text-sm font-bold text-slate-700">Service Interested In</label>
                                        <input name="service" value={formData.service} onChange={handleChange} type="text" className="w-full px-4 py-3 rounded-lg border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-200 outline-none transition bg-slate-50 font-medium text-slate-700" placeholder="e.g. GST Filing" />
                                    </div>

                                    <div className="space-y-2">
                                        <label className="text-sm font-bold text-slate-700">Message (Optional)</label>
                                        <textarea name="message" value={formData.message} onChange={handleChange} rows="4" className="w-full px-4 py-3 rounded-lg border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-200 outline-none transition" placeholder="Tell us more about your requirements..."></textarea>
                                    </div>

                                    <button disabled={isSubmitting} type="submit" className="w-full bg-red-600 text-white font-bold py-4 rounded-xl hover:bg-red-700 transition shadow-lg shadow-red-600/20 flex items-center justify-center">
                                        {isSubmitting ? <Loader2 className="w-5 h-5 animate-spin" /> : <>Send Inquiry <Send className="w-4 h-4 ml-2" /></>}
                                    </button>
                                </form>
                            )}
                        </div>

                    </div>
                </div>
            </main>

            <Footer />
        </div>
    );
};

export default ContactUsPage;
