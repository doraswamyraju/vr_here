/**
 * Standalone Answer Engine Optimization (AEO) Scoring & Diagnostic Engine
 * Decoupled client-side analysis tool evaluating content compatibility for
 * AI-driven search (Google SGE, Perplexity, ChatGPT, Gemini, etc.).
 */

export const analyzeAeo = (contentHtml, focusKeywords = [], faqList = [], seoSettings = {}) => {
    const diagnostics = [];
    let score = 100;

    // Helper: strip HTML to get raw text
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = contentHtml || '';
    const rawText = tempDiv.textContent || tempDiv.innerText || '';

    // 1. Structured Data / Schema Markup Analysis (JSON-LD)
    // In our live setup, we inject schema scripts in the head. We can check if dynamic FAQ or Product schemas are generated.
    // If faqList contains items, we assume a schema *can* or *is* generated. Let's check for actual structured formatting.
    const schemas = [];
    const scriptTags = document.getElementsByTagName('script');
    let hasJsonLd = false;
    let schemaTypes = [];

    for (let i = 0; i < scriptTags.length; i++) {
        if (scriptTags[i].getAttribute('type') === 'application/ld+json') {
            hasJsonLd = true;
            try {
                const json = JSON.parse(scriptTags[i].textContent);
                const type = json['@type'] || (json['@graph'] && json['@graph'][0] && json['@graph'][0]['@type']);
                if (type) {
                    schemaTypes.push(type);
                }
            } catch (e) {
                // Ignore parsing errors of other scripts
            }
        }
    }

    // Since this runs within our customizer before injecting to main document, we also verify if faqList is populated
    if (faqList && faqList.length > 0) {
        hasJsonLd = true;
        schemaTypes.push('FAQPage');
    }

    if (!hasJsonLd) {
        score -= 25;
        diagnostics.push({
            type: 'error',
            module: 'aeo',
            label: 'JSON-LD Schema Markup',
            message: 'No Structured Data (JSON-LD Schema) detected. Answer Engines rely on structured schemas to extract precise data points.'
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'aeo',
            label: 'JSON-LD Schema Markup',
            message: `JSON-LD Schema detected (Types: ${schemaTypes.join(', ')}). Great for Perplexity and Google rich snippets.`
        });
    }

    // 2. Direct Answer Paragraph Analysis
    // Check if there are short paragraphs containing a definition syntax: "X is..." or "Y is a..."
    const paragraphs = tempDiv.getElementsByTagName('p');
    let hasConciseDefinition = false;
    let paragraphLengths = [];

    const activeKeyword = focusKeywords[0] || '';

    for (let i = 0; i < paragraphs.length; i++) {
        const text = paragraphs[i].textContent.trim();
        paragraphLengths.push(text.length);

        if (activeKeyword && text.toLowerCase().includes(activeKeyword.toLowerCase())) {
            const isDefinition = /\bis\b|\brefers to\b|\bmeans\b/i.test(text);
            if (isDefinition && text.length >= 100 && text.length <= 280) {
                hasConciseDefinition = true;
            }
        }
    }

    if (activeKeyword) {
        if (!hasConciseDefinition) {
            score -= 15;
            diagnostics.push({
                type: 'warning',
                module: 'aeo',
                label: 'Direct Answer Snippet',
                message: `Could not find a concise definition snippet (100-280 chars) for "${activeKeyword}". Create a short, straightforward "X is..." sentence in the first paragraph.`
            });
        } else {
            diagnostics.push({
                type: 'success',
                module: 'aeo',
                label: 'Direct Answer Snippet',
                message: `Optimal concise definition snippet detected for "${activeKeyword}". Perfect for SGE and featured snippet cards.`
            });
        }
    }

    // 3. Conversational Heading Questions (Q&A Style)
    // Answer engines respond directly to questions. Look for headings with "what", "how", "why", "who", "when", "?"
    const headings = [...tempDiv.getElementsByTagName('h1'), ...tempDiv.getElementsByTagName('h2'), ...tempDiv.getElementsByTagName('h3'), ...tempDiv.getElementsByTagName('h4')];
    let questionHeadingsCount = 0;
    
    headings.forEach(heading => {
        const text = heading.textContent.trim().toLowerCase();
        const isQuestion = /what|how|why|who|when|where|which|\?/i.test(text);
        if (isQuestion) {
            questionHeadingsCount++;
        }
    });

    if (questionHeadingsCount < 2) {
        score -= 15;
        diagnostics.push({
            type: 'warning',
            module: 'aeo',
            label: 'Conversational Headings',
            message: `Only found ${questionHeadingsCount} question-based headings. Phrase at least 2 heading tags as direct questions (e.g. "What is Private Limited Registration?") to match user voice queries.`
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'aeo',
            label: 'Conversational Headings',
            message: `Found ${questionHeadingsCount} conversational question headings. Highly optimized for query-matching.`
        });
    }

    // 4. Structured Lists & Tables Check
    const uls = tempDiv.getElementsByTagName('ul');
    const ols = tempDiv.getElementsByTagName('ol');
    const tables = tempDiv.getElementsByTagName('table');
    const totalStructures = uls.length + ols.length + tables.length;

    if (totalStructures < 2) {
        score -= 15;
        diagnostics.push({
            type: 'warning',
            module: 'aeo',
            label: 'Data Structuring',
            message: `Few structured elements found (Lists/Tables: ${totalStructures}). LLMs and SGE heavily favor bulleted highlights or formatted data tables to digest features.`
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'aeo',
            label: 'Data Structuring',
            message: `Great use of bulleted layouts/tables (${totalStructures} lists or tables). Ideal format for AI summarizers.`
        });
    }

    // 5. Readability / Simple Authority Tone
    // Simple Flesch-Kincaid style heuristic: average word size. Longer average words mean high vocabulary complexity.
    const words = rawText.trim().split(/\s+/).filter(w => w.length > 0);
    let totalCharLength = 0;
    words.forEach(w => totalCharLength += w.replace(/[^a-zA-Z]/g, '').length);
    const avgWordLength = words.length > 0 ? (totalCharLength / words.length) : 0;

    if (avgWordLength > 6.2) {
        score -= 10;
        diagnostics.push({
            type: 'warning',
            module: 'aeo',
            label: 'Language Complexity',
            message: `High average word complexity (${avgWordLength.toFixed(1)} chars). AI engines prefer straightforward, clear, easily parsed explanations. Simplify vocabulary.`
        });
    } else {
        diagnostics.push({
            type: 'success',
            module: 'aeo',
            label: 'Language Complexity',
            message: `Perfect readability profile (${avgWordLength.toFixed(1)} average characters per word). Easily digestible for LLM tokenizers.`
        });
    }

    // Final bound check
    const finalScore = Math.max(0, Math.min(100, score));

    return {
        score: finalScore,
        diagnostics
    };
};
