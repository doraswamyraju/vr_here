# Standalone SEO/AEO Analyzer & Tracking Module Changelog

## v1.1
- **Initial Setup**: Established initial modular split under `v1.1`.
- **Standalone Scoring Engine**: Added `seoEngine.js` and `aeoEngine.js` for evaluation of traditional indexing criteria (density, headings, description) and Modern AI Search Engine factors (SGE direct answers, conversational queries, list densities, schema LD-JSON presence).
- **Google Search Console Integration**: Visual charts utilizing Recharts in `GscMetricsDashboard.jsx` drawing live metrics (impressions, positions, clicks) using secure Google APIs.
- **Dynamic Trackers Injections**: Custom GA4 and Meta Pixel configuration interface inside `TrackingSettings.jsx` dynamically generating tag inclusions at runtime.
- **Premium Glass Drawer**: A slide-out responsive overlay panel with interactive grading circular score dials and organic keyword search mockup snippets.
