import React, { useEffect, useState } from 'react';
import { SharedHeader, SharedFooter } from './components/SharedComponents';

const sections = [
    {
        title: '1. Introduction',
        content:
            'VR HERE Business Management Solutions ("VR HERE", "we", "us", or "our") values your privacy. This Privacy Policy explains how we collect, use, disclose, and protect your information when you use our website (vrhere.in) and our mobile applications (iOS and Android). By using our services, you consent to the data practices described in this policy.'
    },
    {
        title: '2. Information We Collect',
        content:
            'We collect information to provide better services to our clients: \n• Personal Details: Name, email address, phone number, and account credentials.\n• Business Information: Business name, registration details, GSTIN, PAN, and other tax/legal identifiers.\n• Documents & Uploads: Financial records, invoices, bank statements, and statutory certificates uploaded by you for compliance filing.\n• Device Data: IP address, device type, operating system, and crash logs to improve app performance.'
    },
    {
        title: '3. Mobile App Permissions',
        content:
            'Our iOS and Android applications may request the following permissions to function correctly:\n• Camera & Photo Library: Required to let you scan and upload tax invoices, receipts, and compliance documents directly from your device.\n• Push Notifications: Used to send you critical updates about filing deadlines, order status changes, and support ticket resolutions.'
    },
    {
        title: '4. How We Use Your Information',
        content:
            'We use the collected data for the following purposes:\n• To deliver accounting, bookkeeping, GST filing, and business registration services.\n• To manage customer accounts, support tickets, and process payments securely.\n• To communicate important statutory updates, compliance reminders, and promotional offers.\n• To detect, prevent, and address technical issues or security threats.'
    },
    {
        title: '5. Account and Data Deletion (App & Web)',
        content:
            'We respect your right to control your data. If you wish to delete your VR HERE account and associated business data, you can do so easily:\n• Option A (In-App): Go to your profile settings inside the iOS/Android app and click "Delete Account".\n• Option B (Email): Send an email request to vrherebms@gmail.com with the subject line "Account Deletion Request". Please mention your registered phone number or email address.\n\nUpon receiving your request, we will verify your identity and permanently delete your account, personal information, and uploaded business files from our active databases within 7 business days, except where retention is required by Indian law (e.g., tax records, audit trials).'
    },
    {
        title: '6. Data Security and Third Parties',
        content:
            'We implement industry-standard security measures to safeguard your sensitive documents. We do not sell or rent your data. We share details only with trusted services necessary to perform our operations:\n• Razorpay: For secure payment processing.\n• LiveChat: For real-time customer support.\n• Government Portals: We transmit documents to official government portals (GSTN, Income Tax department, MCA) solely to file returns as authorized by you.'
    },
    {
        title: '7. Changes to this Policy',
        content:
            'We may update this Privacy Policy from time to time. We will notify you of any material changes by posting the new policy on this page and updating the "Last Updated" date at the bottom.'
    },
    {
        title: '8. Contact Us',
        content:
            'If you have any questions, feedback, or concerns regarding this Privacy Policy or account deletion, please contact us at:\n• Email: vrherebms@gmail.com\n• Phone: +91 80085 30606\n• Address: VR HERE Business Management Solutions, Hyderabad, Telangana, India.'
    }
];

const PrivacyPolicyPage = () => {
    const [isScrolled, setIsScrolled] = useState(false);

    useEffect(() => {
        const onScroll = () => setIsScrolled(window.scrollY > 20);
        window.addEventListener('scroll', onScroll);
        return () => window.removeEventListener('scroll', onScroll);
    }, []);

    return (
        <div className="min-h-screen bg-slate-50 text-slate-800">
            <SharedHeader isScrolled={isScrolled} />
            <section className="pt-24 pb-14 bg-slate-900 text-white">
                <div className="max-w-5xl mx-auto px-4">
                    <h1 className="text-4xl md:text-5xl font-black">Privacy Policy</h1>
                    <p className="mt-4 text-slate-300 max-w-3xl">
                        Last Updated: July 2026. This policy outlines how we handle data for VR HERE services, including web and mobile platforms.
                    </p>
                </div>
            </section>

            <section className="max-w-5xl mx-auto px-4 py-10 space-y-6">
                {sections.map((section) => (
                    <article key={section.title} className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
                        <h2 className="text-xl font-bold text-slate-900 mb-3">{section.title}</h2>
                        <p className="text-slate-600 leading-relaxed whitespace-pre-line">{section.content}</p>
                    </article>
                ))}
            </section>
            <SharedFooter />
        </div>
    );
};

export default PrivacyPolicyPage;
