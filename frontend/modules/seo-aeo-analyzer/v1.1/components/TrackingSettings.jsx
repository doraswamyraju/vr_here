import React, { useState, useEffect } from 'react';
import { Shield, Sparkles, CheckCircle2, AlertCircle, Save, HelpCircle } from 'lucide-react';

// Dynamic Script Injector Helper
export const injectTrackingScripts = (googleAnalyticsId, metaPixelId) => {
    // 1. Google Analytics (GA4) Injection
    if (googleAnalyticsId && googleAnalyticsId.trim().startsWith('G-')) {
        const gaId = googleAnalyticsId.trim();
        
        // Check if already injected to prevent duplicates
        if (!document.getElementById('gsc-ga4-script')) {
            const script = document.createElement('script');
            script.id = 'gsc-ga4-script';
            script.src = `https://www.googletagmanager.com/gtag/js?id=${gaId}`;
            script.async = true;
            document.head.appendChild(script);

            const inlineScript = document.createElement('script');
            inlineScript.id = 'gsc-ga4-inline';
            inlineScript.textContent = `
                window.dataLayer = window.dataLayer || [];
                function gtag(){dataLayer.push(arguments);}
                gtag('js', new Date());
                gtag('config', '${gaId}');
            `;
            document.head.appendChild(inlineScript);
            console.log(`[Tracking] Dynamically injected GA4 script (${gaId})`);
        }
    }

    // 2. Meta Pixel Injection
    if (metaPixelId && metaPixelId.trim().length > 3) {
        const pixelId = metaPixelId.trim();
        
        if (!document.getElementById('gsc-meta-pixel')) {
            const inlineScript = document.createElement('script');
            inlineScript.id = 'gsc-meta-pixel';
            inlineScript.textContent = `
                !function(f,b,e,v,n,t,s)
                {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
                n.callMethod.apply(n,arguments):n.queue.push(arguments)};
                if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
                n.queue=[];t=b.createElement(e);t.async=!0;
                t.src=v;s=b.getElementsByTagName(e)[0];
                s.parentNode.insertBefore(t,s)}(window, document,'script',
                'https://connect.facebook.net/en_US/fbevents.js');
                fbq('init', '${pixelId}');
                fbq('track', 'PageView');
            `;
            document.head.appendChild(inlineScript);

            // Add no script fallback
            const noScript = document.createElement('noscript');
            noScript.id = 'gsc-meta-pixel-noscript';
            noScript.innerHTML = `<img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id=${pixelId}&ev=PageView&noscript=1" />`;
            document.body.appendChild(noScript);
            console.log(`[Tracking] Dynamically injected Meta Pixel script (${pixelId})`);
        }
    }
};

const TrackingSettings = ({ initialSettings = {}, onSave, isSaving }) => {
    const [gaId, setGaId] = useState(initialSettings.googleAnalyticsId || '');
    const [metaId, setMetaId] = useState(initialSettings.metaPixelId || '');
    const [saveSuccess, setSaveSuccess] = useState(false);

    useEffect(() => {
        setGaId(initialSettings.googleAnalyticsId || '');
        setMetaId(initialSettings.metaPixelId || '');
    }, [initialSettings]);

    const handleSubmit = (e) => {
        e.preventDefault();
        onSave({
            googleAnalyticsId: gaId,
            metaPixelId: metaId
        });
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 3000);
    };

    return (
        <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex items-center space-x-2 text-indigo-400 border-b border-slate-800 pb-3">
                <Shield className="w-5 h-5" />
                <h3 className="font-bold text-sm tracking-wide uppercase text-white">Tracking & Performance Setup</h3>
            </div>
            
            <p className="text-xs text-slate-400 leading-relaxed font-medium">
                Connect tracking engines directly to analyze user conversions. Tracking scripts are dynamically injected at runtime, ensuring clean page setups.
            </p>

            <div className="space-y-4">
                <div>
                    <label className="block text-xs font-black uppercase text-slate-300 tracking-wider mb-2 flex items-center gap-1.5">
                        Google Analytics Measurement ID
                        <HelpCircle className="w-3.5 h-3.5 text-slate-500 cursor-help" title="GA4 measurement ID starts with 'G-'" />
                    </label>
                    <input
                        type="text"
                        placeholder="G-XXXXXXXXXX"
                        value={gaId}
                        onChange={(e) => setGaId(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700/60 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
                    />
                </div>

                <div>
                    <label className="block text-xs font-black uppercase text-slate-300 tracking-wider mb-2 flex items-center gap-1.5">
                        Meta Pixel ID
                        <HelpCircle className="w-3.5 h-3.5 text-slate-500 cursor-help" title="Your standard 15-digit Meta Pixel ID" />
                    </label>
                    <input
                        type="text"
                        placeholder="e.g. 157294657193740"
                        value={metaId}
                        onChange={(e) => setMetaId(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700/60 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
                    />
                </div>
            </div>

            <div className="bg-slate-900/40 p-4 rounded-xl border border-slate-800/80 flex items-start gap-3">
                <Sparkles className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
                <div className="text-[10px] text-slate-400 font-semibold leading-relaxed">
                    Once saved, the service page will automatically load these trackers for public visitors. Custom events (like clicking 'Select Plan') are fired automatically to measure user conversion rates!
                </div>
            </div>

            <button
                type="submit"
                disabled={isSaving}
                className="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-bold py-3.5 px-4 rounded-xl text-xs uppercase tracking-widest shadow-lg shadow-indigo-600/25 active:scale-95 transform transition-all flex items-center justify-center gap-2"
            >
                {isSaving ? (
                    <span>Saving...</span>
                ) : (
                    <>
                        <Save className="w-4 h-4" />
                        <span>Save Tracking Integration</span>
                    </>
                )}
            </button>

            {saveSuccess && (
                <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 p-3 rounded-lg flex items-center gap-2 text-xs font-semibold animate-fade-in">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Tracking settings saved and loaded successfully!</span>
                </div>
            )}
        </form>
    );
};

export default TrackingSettings;
