/**
 * Standalone Real-time SEO Scoring & Diagnostic Engine
 * Decoupled client-side analysis tool.
 */

export const analyzeSeo = (contentHtml, focusKeywords = [], seoSettings = {}) => {
    const diagnostics = [];
    let score = 100;

    // Helper: strip HTML to get raw text
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = contentHtml || '';
    const rawText = tempDiv.textContent || tempDiv.innerText || '';
    const words = rawText.trim().split(/\s+/).filter(w => w.length > 0);
    const wordCount = words.length;

    // 1. Word Count Diagnostic
    if (wordCount < 300) {
        score -= 20;
        diagnostics.push({
            type: 'error',
            module: 'seo',
            label: 'Content Length',
            message: `Very short content (${wordCount} words). Aim for at least 300-600 words for landing service pages.`
        });
    } else if (wordCount < 600) {
        score -= 10;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Content Length',
            message: `Moderate content length (${wordCount} words). Adding more detailed sections can improve indexing.`
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'seo',
            label: 'Content Length',
            message: `Great content length (${wordCount} words)! Fully detailed and informative.`
        });
    }

    // Helper: Find matches of keywords
    const getKeywordMatches = (text, keyword) => {
        if (!keyword) return 0;
        const escaped = keyword.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(`\\b${escaped}\\b`, 'gi');
        return (text.match(regex) || []).length;
    };

    // 2. Focus Keywords Density
    const activeKeyword = focusKeywords[0] || '';
    if (activeKeyword) {
        const matches = getKeywordMatches(rawText, activeKeyword);
        const density = wordCount > 0 ? ((matches / wordCount) * 100) : 0;

        if (matches === 0) {
            score -= 20;
            diagnostics.push({
                type: 'error',
                module: 'seo',
                label: 'Focus Keyword Usage',
                message: `Focus keyword "${activeKeyword}" not found in the body text. Make sure to use it naturally.`
            });
        } else if (density > 3.0) {
            score -= 10;
            diagnostics.push({
                type: 'warning',
                module: 'seo',
                label: 'Keyword Stuffing',
                message: `High keyword density (${density.toFixed(2)}%). Focus keyword matches ${matches} times. Reduce it to avoid stuffing flags.`
            });
        } else if (density < 0.5) {
            score -= 5;
            diagnostics.push({
                type: 'warning',
                module: 'seo',
                label: 'Focus Keyword Density',
                message: `Low keyword density (${density.toFixed(2)}%). Try to use it slightly more often in headings or description.`
            });
        } else {
            diagnostics.push({
                type: 'success',
                module: 'seo',
                label: 'Focus Keyword Density',
                message: `Optimal keyword density (${density.toFixed(2)}% - matched ${matches} times).`
            });
        }

        // Focus Keyword in Title
        const titleTag = seoSettings.titleTag || '';
        if (titleTag && !titleTag.toLowerCase().includes(activeKeyword.toLowerCase())) {
            score -= 10;
            diagnostics.push({
                type: 'warning',
                module: 'seo',
                label: 'Keyword in Title',
                message: `Focus keyword "${activeKeyword}" is missing from the Meta Title Tag.`
            });
        } else if (titleTag) {
            diagnostics.push({
                type: 'success',
                module: 'seo',
                label: 'Keyword in Title',
                message: `Focus keyword is present in the Meta Title Tag.`
            });
        }

        // Focus Keyword in Meta Description
        const metaDesc = seoSettings.metaDescription || '';
        if (metaDesc && !metaDesc.toLowerCase().includes(activeKeyword.toLowerCase())) {
            score -= 10;
            diagnostics.push({
                type: 'warning',
                module: 'seo',
                label: 'Keyword in Meta Description',
                message: `Focus keyword "${activeKeyword}" is missing from the Meta Description.`
            });
        } else if (metaDesc) {
            diagnostics.push({
                type: 'success',
                module: 'seo',
                label: 'Keyword in Meta Description',
                message: `Focus keyword is present in the Meta Description.`
            });
        }
    } else {
        score -= 15;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Focus Keyword Specified',
            message: 'No focus keyword is set for this page. Add focus keywords to activate density metrics.'
        });
    }

    // 3. Headings Structure Analysis
    const h1s = tempDiv.getElementsByTagName('h1');
    const h2s = tempDiv.getElementsByTagName('h2');
    const h3s = tempDiv.getElementsByTagName('h3');

    if (h1s.length === 0) {
        score -= 15;
        diagnostics.push({
            type: 'error',
            module: 'seo',
            label: 'H1 Heading Tag',
            message: 'No H1 heading tag found. Add exactly one H1 tag per page for correct SEO hierarchy.'
        });
    } else if (h1s.length > 1) {
        score -= 10;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Multiple H1 Tags',
            message: `Found ${h1s.length} H1 tags. Keep exactly one H1 heading tag and convert others to H2s.`
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'seo',
            label: 'H1 Heading Tag',
            message: 'Excellent. Exactly one H1 heading tag is present.'
        });
    }

    if (h2s.length === 0) {
        score -= 5;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Subheading Structure (H2)',
            message: 'No H2 subheadings found. Break your content into H2 section headings to improve structure.'
        });
    }

    // 4. Meta Description Length Check
    const metaDesc = seoSettings.metaDescription || '';
    if (!metaDesc) {
        score -= 20;
        diagnostics.push({
            type: 'error',
            module: 'seo',
            label: 'Meta Description',
            message: 'Meta Description is missing. Search engines will default to random body snippets.'
        });
    } else if (metaDesc.length < 110) {
        score -= 5;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Meta Description Length',
            message: `Meta Description is too short (${metaDesc.length} chars). Aim for 120-160 characters to optimize SERP real estate.`
        });
    } else if (metaDesc.length > 165) {
        score -= 5;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Meta Description Length',
            message: `Meta Description is too long (${metaDesc.length} chars). Keep it under 160 characters to prevent snippets truncation.`
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'seo',
            label: 'Meta Description Length',
            message: `Optimal Meta Description length (${metaDesc.length} characters).`
        });
    }

    // 5. Image Alternative (alt) Tags
    const images = tempDiv.getElementsByTagName('img');
    let missingAlts = 0;
    for (let i = 0; i < images.length; i++) {
        if (!images[i].getAttribute('alt')) {
            missingAlts++;
        }
    }

    if (images.length > 0) {
        if (missingAlts > 0) {
            score -= Math.min(10, missingAlts * 2);
            diagnostics.push({
                type: 'warning',
                module: 'seo',
                label: 'Image Alternative (alt) Text',
                message: `Found ${missingAlts} out of ${images.length} images missing alt text attributes.`
            });
        } else {
            diagnostics.push({
                type: 'success',
                module: 'seo',
                label: 'Image Alternative (alt) Text',
                message: 'All images on the page have descriptive alt text attributes.'
            });
        }
    }

    // 6. Link Distribution (Internal / External)
    const links = tempDiv.getElementsByTagName('a');
    let externalLinks = 0;
    let internalLinks = 0;
    for (let i = 0; i < links.length; i++) {
        const href = links[i].getAttribute('href') || '';
        if (href.startsWith('http') && !href.includes('vrhere.in') && !href.includes('localhost')) {
            externalLinks++;
        } else if (href.length > 0 && !href.startsWith('#') && !href.startsWith('javascript:')) {
            internalLinks++;
        }
    }

    if (internalLinks === 0) {
        score -= 5;
        diagnostics.push({
            type: 'warning',
            module: 'seo',
            label: 'Internal Links',
            message: 'No internal links found. Link to other services to improve crawlability and page rank distribution.'
        });
    }

    // Final Bound check
    const finalScore = Math.max(0, Math.min(100, score));

    return {
        score: finalScore,
        diagnostics
    };
};
