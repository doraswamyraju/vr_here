import React, { useState, useEffect } from 'react';
import { 
    AlertCircle, Sparkles, CheckCircle2, ChevronRight, ChevronDown, 
    Play, Eye, ShieldAlert, BarChart2, Award, Zap, Globe, Search, Link, ExternalLink 
} from 'lucide-react';
import { analyzeSeo } from '../core/seoEngine';
import { analyzeAeo } from '../core/aeoEngine';
import GscMetricsDashboard from './GscMetricsDashboard';
import TrackingSettings from './TrackingSettings';
import axios from 'axios';

const SeoAeoDashboard = ({ pageId, currentHtml = '', faqList = [], seoSettings = {}, onUpdateSeoSettings, trackingSettings = {}, onUpdateTrackingSettings, config, isSaving }) => {
    const [activeTab, setActiveTab] = useState('analysis');
    const [isOpen, setIsOpen] = useState(false);
    const [seoResult, setSeoResult] = useState({ score: 0, diagnostics: [] });
    const [aeoResult, setAeoResult] = useState({ score: 0, diagnostics: [] });
    const [expandedGroup, setExpandedGroup] = useState('errors');

    // Run real-time scoring evaluations whenever inputs modify
    useEffect(() => {
        const keywords = seoSettings.focusKeywords || [];
        const seoRes = analyzeSeo(currentHtml, keywords, seoSettings);
        const aeoRes = analyzeAeo(currentHtml, keywords, faqList, seoSettings);
        setSeoResult(seoRes);
        setAeoResult(aeoRes);
    }, [currentHtml, faqList, seoSettings]);

    // Triggers GSC Connection OAuth flow
    const handleGscAuth = async () => {
        try {
            const token = localStorage.getItem('token') || (JSON.parse(localStorage.getItem('userInfo'))?.token);
            const res = await axios.get(`/api/service-pages/${pageId}/gsc/auth`, {
                headers: { Authorization: `Bearer ${token}` }
            });
            if (res.data && res.data.authUrl) {
                window.location.href = res.data.authUrl;
            }
        } catch (err) {
            alert('Failed to initialize GSC link. Check client configurations.');
        }
    };

    // Diagnostics filtering
    const allDiagnostics = [...seoResult.diagnostics, ...aeoResult.diagnostics];
    const errors = allDiagnostics.filter(d => d.type === 'error');
    const warnings = allDiagnostics.filter(d => d.type === 'warning');
    const passes = allDiagnostics.filter(d => d.type === 'success');

    // Score radial values
    const seoCircumference = 2 * Math.PI * 26;
    const aeoCircumference = 2 * Math.PI * 26;
    const seoOffset = seoCircumference - (seoResult.score / 100) * seoCircumference;
    const aeoOffset = aeoCircumference - (aeoResult.score / 100) * aeoCircumference;

    return (
        <>
            {/* FLOATING ACTION TRIGGER */}
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="fixed bottom-24 right-6 z-[80] bg-slate-950 text-white border border-slate-800 hover:border-indigo-500 py-3.5 px-5 rounded-2xl font-black text-xs uppercase tracking-widest shadow-2xl flex items-center gap-2.5 transition transform hover:-translate-y-1 active:scale-95 group"
            >
                <div className="relative">
                    <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-indigo-500 rounded-full animate-ping"></span>
                    <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-indigo-500 rounded-full"></span>
                    <Sparkles className="w-4 h-4 text-indigo-400 group-hover:rotate-12 transition-transform" />
                </div>
                <span>Live SEO/AEO Optimizer</span>
            </button>

            {/* EXPANDABLE OPTIMIZER DRAWER */}
            <div className={`fixed top-0 right-0 h-screen w-full md:w-[480px] bg-slate-950/95 backdrop-blur-xl border-l border-slate-900 z-[90] shadow-2xl transform transition-transform duration-500 ease-out flex flex-col ${isOpen ? 'translate-x-0' : 'translate-x-full'}`}>
                {/* Header bar */}
                <div className="p-6 border-b border-slate-900 flex items-center justify-between">
                    <div>
                        <div className="flex items-center gap-2">
                            <h2 className="text-base font-black text-white uppercase tracking-wider">SEO & AEO OPTIMIZER</h2>
                            <span className="text-[9px] font-black tracking-widest bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded uppercase">Live Core v1.1</span>
                        </div>
                        <p className="text-[10px] text-slate-500 font-bold uppercase mt-1">Real-time grader & search auditor</p>
                    </div>
                    <button
                        onClick={() => setIsOpen(false)}
                        className="text-xs uppercase font-black tracking-widest text-slate-500 hover:text-white transition"
                    >
                        Close [x]
                    </button>
                </div>

                {/* Dashboard Tab Items */}
                <div className="flex border-b border-slate-900 text-xs font-bold bg-slate-950/30">
                    <button
                        onClick={() => setActiveTab('analysis')}
                        className={`flex-1 py-4 text-center border-b-2 transition ${activeTab === 'analysis' ? 'border-indigo-500 text-white' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
                    >
                        Live Grades
                    </button>
                    <button
                        onClick={() => setActiveTab('gsc')}
                        className={`flex-1 py-4 text-center border-b-2 transition ${activeTab === 'gsc' ? 'border-indigo-500 text-white' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
                    >
                        Google Analytics
                    </button>
                    <button
                        onClick={() => setActiveTab('tracking')}
                        className={`flex-1 py-4 text-center border-b-2 transition ${activeTab === 'tracking' ? 'border-indigo-500 text-white' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
                    >
                        Pixel & GA4
                    </button>
                </div>

                {/* SCROLLABLE CONTENT */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6 scrollbar-thin scrollbar-thumb-slate-800">
                    {activeTab === 'analysis' && (
                        <div className="space-y-6">
                            {/* DUAL RADIAL SCORES METER */}
                            <div className="grid grid-cols-2 gap-4">
                                {/* SEO Meter */}
                                <div className="bg-slate-900/40 p-4 rounded-2xl border border-slate-900 flex items-center justify-between">
                                    <div>
                                        <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">SEO Score</div>
                                        <div className="text-xs text-slate-500 font-bold mt-1">Traditional SERP</div>
                                    </div>
                                    <div className="relative w-16 h-16 flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="32" cy="32" r="26" stroke="#1e293b" strokeWidth="4" fill="transparent" />
                                            <circle cx="32" cy="32" r="26" stroke={seoResult.score > 70 ? '#10b981' : seoResult.score > 40 ? '#f59e0b' : '#ef4444'} strokeWidth="4" fill="transparent" strokeDasharray={seoCircumference} strokeDashoffset={seoOffset} strokeLinecap="round" className="transition-all duration-700" />
                                        </svg>
                                        <span className="absolute font-black text-sm text-white">{seoResult.score}</span>
                                    </div>
                                </div>

                                {/* AEO Meter */}
                                <div className="bg-slate-900/40 p-4 rounded-2xl border border-slate-900 flex items-center justify-between">
                                    <div>
                                        <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">AEO Score</div>
                                        <div className="text-xs text-slate-500 font-bold mt-1">AI Engines & SGE</div>
                                    </div>
                                    <div className="relative w-16 h-16 flex items-center justify-center">
                                        <svg className="w-full h-full transform -rotate-90">
                                            <circle cx="32" cy="32" r="26" stroke="#1e293b" strokeWidth="4" fill="transparent" />
                                            <circle cx="32" cy="32" r="26" stroke={aeoResult.score > 70 ? '#818cf8' : aeoResult.score > 40 ? '#f59e0b' : '#ef4444'} strokeWidth="4" fill="transparent" strokeDasharray={aeoCircumference} strokeDashoffset={aeoOffset} strokeLinecap="round" className="transition-all duration-700" />
                                        </svg>
                                        <span className="absolute font-black text-sm text-white">{aeoResult.score}</span>
                                    </div>
                                </div>
                            </div>

                            {/* FOCUS KEYWORD AND METADATA EDIT PREVIEW */}
                            <div className="bg-slate-900/30 p-4 rounded-2xl border border-slate-900 space-y-4">
                                <h3 className="text-xs font-black uppercase text-slate-300 tracking-wider">Search Focus Keyword</h3>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        placeholder="e.g. Private Limited Company"
                                        value={seoSettings.focusKeywords?.[0] || ''}
                                        onChange={(e) => {
                                            const updated = { ...seoSettings, focusKeywords: [e.target.value] };
                                            onUpdateSeoSettings(updated);
                                        }}
                                        className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500 transition"
                                    />
                                </div>
                            </div>

                            {/* REAL-TIME SNIPPET MOCKUPS PREVIEWS */}
                            <div className="bg-slate-900/30 p-4 rounded-2xl border border-slate-900 space-y-4">
                                <h3 className="text-xs font-black uppercase text-slate-300 tracking-wider flex items-center gap-1.5">
                                    <Eye className="w-4 h-4 text-indigo-400" />
                                    <span>Google Search Snippet Preview</span>
                                </h3>
                                <div className="bg-white p-4 rounded-xl shadow-inner border border-slate-100 font-sans text-left">
                                    <div className="text-[11px] text-slate-600 flex items-center gap-1 font-medium">
                                        <span>https://vrhere.in</span>
                                        <ChevronRight className="w-2.5 h-2.5" />
                                        <span>{pageId === 'private-limited' ? 'pvt-ltd-registration' : pageId}</span>
                                    </div>
                                    <div className="text-indigo-800 hover:underline text-sm font-semibold mt-1 leading-snug cursor-pointer">
                                        {seoSettings.titleTag || `${config?.title || 'Service Details'} | VR Here`}
                                    </div>
                                    <div className="text-xs text-slate-600 leading-normal mt-1 font-medium">
                                        {seoSettings.metaDescription || 'Add a Meta Description to preview exactly how this service will appear inside organic Google search results snippets.'}
                                    </div>
                                </div>

                                <h3 className="text-xs font-black uppercase text-slate-300 tracking-wider flex items-center gap-1.5 mt-6">
                                    <Award className="w-4 h-4 text-indigo-400 animate-pulse" />
                                    <span>AI Answer Engine Citation Snippet (SGE / Perplexity Mockup)</span>
                                </h3>
                                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl text-left space-y-3 font-sans">
                                    <div className="flex items-center gap-2">
                                        <div className="bg-indigo-500/10 text-indigo-400 w-5 h-5 rounded flex items-center justify-center font-bold text-[9px]">AI</div>
                                        <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">Engine Answer Synthesis</span>
                                    </div>
                                    <div className="text-xs text-slate-300 leading-relaxed font-semibold">
                                        {seoResult.score > 75 ? (
                                            `Yes, VR Here provides comprehensive ${config?.title || 'support'} services. They offer an all-inclusive dynamic package cover. According to their specifications, they ensure complete CA/CS expert oversight and fast delivery.`
                                        ) : (
                                            'Content AEO scores are too low to synthesize direct citations. Phrase sections clearly as direct definition answers, add list highlights, and configure JSON-LD schemas to activate Rich AI Answers.'
                                        )}
                                    </div>
                                    {seoResult.score > 75 && (
                                        <div className="flex items-center gap-2 pt-2 border-t border-slate-800/80">
                                            <span className="text-[8px] font-bold text-slate-500 uppercase tracking-widest">Sources Cited:</span>
                                            <a href="#link" className="inline-flex items-center gap-1 bg-indigo-500/10 text-indigo-400 text-[9px] font-bold px-2 py-0.5 rounded border border-indigo-500/20">
                                                <span>1. vrhere.in</span>
                                                <ExternalLink className="w-2.5 h-2.5" />
                                            </a>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* GRADING ACCORDION GROUPS */}
                            <div className="space-y-3">
                                {/* Crucial Failures Accordion */}
                                <div className="border border-slate-900 rounded-xl overflow-hidden">
                                    <button
                                        onClick={() => setExpandedGroup(expandedGroup === 'errors' ? null : 'errors')}
                                        className="w-full bg-slate-900/60 p-4 flex items-center justify-between text-left font-black text-xs tracking-wider uppercase text-slate-300 hover:bg-slate-900 transition"
                                    >
                                        <span className="flex items-center gap-2 text-red-500">
                                            <AlertCircle className="w-4.5 h-4.5" />
                                            <span>CRUCIAL IMPROVEMENTS ({errors.length})</span>
                                        </span>
                                        <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${expandedGroup === 'errors' ? 'rotate-180' : ''}`} />
                                    </button>
                                    {expandedGroup === 'errors' && (
                                        <div className="p-2 bg-slate-950 border-t border-slate-900 space-y-1">
                                            {errors.length === 0 ? (
                                                <div className="p-3 text-slate-500 text-xs font-semibold italic text-center">No major errors found. Fantastic!</div>
                                            ) : (
                                                errors.map((err, idx) => (
                                                    <div key={idx} className="p-3 bg-red-500/5 rounded-lg border border-red-500/10 flex gap-2.5">
                                                        <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                                                        <div className="text-xs">
                                                            <div className="font-bold text-red-400">{err.label}</div>
                                                            <div className="text-[11px] text-slate-400 font-medium leading-relaxed mt-0.5">{err.message}</div>
                                                        </div>
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Warnings Accordion */}
                                <div className="border border-slate-900 rounded-xl overflow-hidden">
                                    <button
                                        onClick={() => setExpandedGroup(expandedGroup === 'warnings' ? null : 'warnings')}
                                        className="w-full bg-slate-900/60 p-4 flex items-center justify-between text-left font-black text-xs tracking-wider uppercase text-slate-300 hover:bg-slate-900 transition"
                                    >
                                        <span className="flex items-center gap-2 text-amber-500">
                                            <AlertCircle className="w-4.5 h-4.5" />
                                            <span>WARNING CHECKS ({warnings.length})</span>
                                        </span>
                                        <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${expandedGroup === 'warnings' ? 'rotate-180' : ''}`} />
                                    </button>
                                    {expandedGroup === 'warnings' && (
                                        <div className="p-2 bg-slate-950 border-t border-slate-900 space-y-1">
                                            {warnings.length === 0 ? (
                                                <div className="p-3 text-slate-500 text-xs font-semibold italic text-center">No warning triggers found. Perfectly clean!</div>
                                            ) : (
                                                warnings.map((warn, idx) => (
                                                    <div key={idx} className="p-3 bg-amber-500/5 rounded-lg border border-amber-500/10 flex gap-2.5">
                                                        <AlertCircle className="w-4.5 h-4.5 text-amber-400 flex-shrink-0 mt-0.5" />
                                                        <div className="text-xs">
                                                            <div className="font-bold text-amber-400">{warn.label}</div>
                                                            <div className="text-[11px] text-slate-400 font-medium leading-relaxed mt-0.5">{warn.message}</div>
                                                        </div>
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    )}
                                </div>

                                {/* Passed Audits Accordion */}
                                <div className="border border-slate-900 rounded-xl overflow-hidden">
                                    <button
                                        onClick={() => setExpandedGroup(expandedGroup === 'passes' ? null : 'passes')}
                                        className="w-full bg-slate-900/60 p-4 flex items-center justify-between text-left font-black text-xs tracking-wider uppercase text-slate-300 hover:bg-slate-900 transition"
                                    >
                                        <span className="flex items-center gap-2 text-emerald-500">
                                            <CheckCircle2 className="w-4.5 h-4.5" />
                                            <span>PASSED AUDITS ({passes.length})</span>
                                        </span>
                                        <ChevronDown className={`w-4 h-4 text-slate-500 transition-transform ${expandedGroup === 'passes' ? 'rotate-180' : ''}`} />
                                    </button>
                                    {expandedGroup === 'passes' && (
                                        <div className="p-2 bg-slate-950 border-t border-slate-900 space-y-1">
                                            {passes.length === 0 ? (
                                                <div className="p-3 text-slate-500 text-xs font-semibold italic text-center">No passed audits yet. Start optimizing!</div>
                                            ) : (
                                                passes.map((pass, idx) => (
                                                    <div key={idx} className="p-3 bg-emerald-500/5 rounded-lg border border-emerald-500/10 flex gap-2.5">
                                                        <CheckCircle2 className="w-4.5 h-4.5 text-emerald-400 flex-shrink-0 mt-0.5" />
                                                        <div className="text-xs">
                                                            <div className="font-bold text-emerald-450">{pass.label}</div>
                                                            <div className="text-[11px] text-slate-500 font-medium leading-relaxed mt-0.5">{pass.message}</div>
                                                        </div>
                                                    </div>
                                                ))
                                            )}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'gsc' && (
                        <GscMetricsDashboard
                            pageId={pageId}
                            config={config}
                            onAuthRequest={handleGscAuth}
                        />
                    )}

                    {activeTab === 'tracking' && (
                        <TrackingSettings
                            initialSettings={trackingSettings}
                            onSave={onUpdateTrackingSettings}
                            isSaving={isSaving}
                        />
                    )}
                </div>
            </div>
        </>
    );
};

export default SeoAeoDashboard;
