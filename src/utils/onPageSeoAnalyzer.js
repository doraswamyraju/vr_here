/**
 * On-Page SEO Analysis Engine
 * Calculates SEO health score (0-100) and provides actionable feedback.
 */

export const analyzeOnPageSeo = ({ focusKeyword = '', titleTag = '', metaDescription = '', pageContent = '', headings = [], slug = '' }) => {
    const issues = [];
    let score = 100;

    const keyword = focusKeyword.trim().toLowerCase();
    const title = titleTag.trim();
    const metaDesc = metaDescription.trim();
    const content = pageContent.trim();

    if (!keyword) {
        return {
            score: 0,
            status: 'warning',
            issues: [{ type: 'error', message: 'Set a Focus Keyword to enable live SEO analysis.' }]
        };
    }

    // 1. Focus Keyword in SEO Title
    if (!title.toLowerCase().includes(keyword)) {
        score -= 20;
        issues.push({ type: 'error', message: 'Focus Keyword does not appear in the SEO Title.' });
    } else if (!title.toLowerCase().startsWith(keyword)) {
        score -= 5;
        issues.push({ type: 'info', message: 'SEO Title starts with non-keyword text. Putting Focus Keyword near the start is recommended.' });
    } else {
        issues.push({ type: 'success', message: 'Focus Keyword appears near the start of the SEO Title.' });
    }

    // 2. SEO Title Length (Optimal 50 - 60 chars)
    if (title.length < 30) {
        score -= 10;
        issues.push({ type: 'warning', message: `SEO Title is too short (${title.length} chars). Aim for 50-60 characters.` });
    } else if (title.length > 60) {
        score -= 10;
        issues.push({ type: 'warning', message: `SEO Title is too long (${title.length} chars). Search engines will truncate it.` });
    } else {
        issues.push({ type: 'success', message: `SEO Title length is optimal (${title.length} characters).` });
    }

    // 3. Focus Keyword in Meta Description
    if (!metaDesc.toLowerCase().includes(keyword)) {
        score -= 20;
        issues.push({ type: 'error', message: 'Focus Keyword does not appear in the Meta Description.' });
    } else {
        issues.push({ type: 'success', message: 'Focus Keyword appears in the Meta Description.' });
    }

    // 4. Meta Description Length (Optimal 120 - 160 chars)
    if (metaDesc.length < 100) {
        score -= 10;
        issues.push({ type: 'warning', message: `Meta Description is short (${metaDesc.length} chars). Aim for 120-160 characters.` });
    } else if (metaDesc.length > 160) {
        score -= 10;
        issues.push({ type: 'warning', message: `Meta Description is long (${metaDesc.length} chars). Aim for under 160 characters.` });
    } else {
        issues.push({ type: 'success', message: `Meta Description length is optimal (${metaDesc.length} characters).` });
    }

    // 5. Keyword in URL Slug
    if (slug && !slug.toLowerCase().includes(keyword.replace(/\s+/g, '-'))) {
        score -= 10;
        issues.push({ type: 'warning', message: 'Focus Keyword is missing from the URL slug.' });
    } else if (slug) {
        issues.push({ type: 'success', message: 'Focus Keyword is present in the URL slug.' });
    }

    // 6. Content Word Count & Density
    const words = content ? content.split(/\s+/).filter(Boolean) : [];
    const wordCount = words.length;

    if (wordCount < 300) {
        score -= 15;
        issues.push({ type: 'warning', message: `Content length is low (${wordCount} words). Recommended minimum is 300-600 words for strong ranking.` });
    } else {
        issues.push({ type: 'success', message: `Content length is strong (${wordCount} words).` });
    }

    if (wordCount > 0) {
        const keywordMatches = (content.toLowerCase().match(new RegExp(keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
        const density = ((keywordMatches / wordCount) * 100).toFixed(1);

        if (density < 0.5) {
            score -= 10;
            issues.push({ type: 'warning', message: `Keyword density is low (${density}%). Aim for 1.0% - 2.5%.` });
        } else if (density > 3.0) {
            score -= 15;
            issues.push({ type: 'error', message: `Keyword density is too high (${density}%). Avoid keyword stuffing.` });
        } else {
            issues.push({ type: 'success', message: `Keyword density is optimal (${density}%).` });
        }
    }

    const finalScore = Math.max(0, Math.min(100, score));

    return {
        score: finalScore,
        status: finalScore >= 80 ? 'good' : finalScore >= 50 ? 'OK' : 'needs-improvement',
        issues
    };
};
