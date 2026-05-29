import SeoAeoDashboard from './components/SeoAeoDashboard';
import { analyzeSeo } from './core/seoEngine';
import { analyzeAeo } from './core/aeoEngine';
import { injectTrackingScripts } from './components/TrackingSettings';

export {
    SeoAeoDashboard,
    analyzeSeo,
    analyzeAeo,
    injectTrackingScripts
};
export default SeoAeoDashboard;
