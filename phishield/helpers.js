// Extraction des caractéristiques d'une URL
export function extractFeatures(url) {
    const urlObj = new URL(url);
    
    return {
        domainLength: urlObj.hostname.length,
        hasHTTPS: urlObj.protocol === 'https:',
        subdomainCount: urlObj.hostname.split('.').length - 1,
        
        pathLength: urlObj.pathname.length,
        queryParamsCount: urlObj.searchParams.size,
        
        hasNumbers: /\d/.test(urlObj.hostname),
        hasSpecialChars: /[^a-zA-Z0-9.]/.test(urlObj.hostname),
        
        hasSuspiciousWords: checkSuspiciousWords(url)
    };
}

function checkSuspiciousWords(url) {
    const suspiciousWords = [
        'login',
        'signin',
        'banking',
        'update',
        'verify'
    ];
    
    const urlLower = url.toLowerCase();
    return suspiciousWords.some(word => urlLower.includes(word));
}

export function normalizeFeatures(features) {
    return {
        domainLength: features.domainLength / 100, // Normalisation par rapport à une longueur max
        hasHTTPS: features.hasHTTPS ? 1 : 0,
        subdomainCount: features.subdomainCount / 5,
        pathLength: features.pathLength / 200,
        queryParamsCount: features.queryParamsCount / 10,
        hasNumbers: features.hasNumbers ? 1 : 0,
        hasSpecialChars: features.hasSpecialChars ? 1 : 0,
        hasSuspiciousWords: features.hasSuspiciousWords ? 1 : 0
    };
}

export function calculateRiskScore(features) {
    const weights = {
        domainLength: 0.1,
        hasHTTPS: 0.2,
        subdomainCount: 0.15,
        pathLength: 0.1,
        queryParamsCount: 0.1,
        hasNumbers: 0.1,
        hasSpecialChars: 0.15,
        hasSuspiciousWords: 0.1
    };
    
    let score = 0;
    const normalizedFeatures = normalizeFeatures(features);
    
    for (const [feature, weight] of Object.entries(weights)) {
        score += normalizedFeatures[feature] * weight;
    }
    
    return Math.min(Math.max(score, 0), 1);
}
