// Configuration des APIs
const CONFIG = {
    VIRUSTOTAL_API_KEY: 'fcdb11759aedc891075e1fe05a05a65d9abb3dae49d828e01389644711506167',
    SAFE_BROWSING_API_KEY: 'AIzaSyDGOAb8tZyf-ycBVcdKPYzUsJ84r54Sjtc',
    CACHE_DURATION: 30 * 60 * 1000, // 30 minutes
    API_ENDPOINTS: {
        VIRUSTOTAL: 'https://www.virustotal.com/vtapi/v2/url',
        SAFE_BROWSING: 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    }
};

// Classe pour l'analyse du contenu
class ContentAnalyzer {
    constructor() {
        this.phishingPatterns = {
            sensitiveKeywords: [
                'password', 'login', 'sign in', 'verify', 'validate', 'confirm',
                'account', 'security', 'update', 'authentication', 'wallet',
                'cryptocurrency', 'bitcoin', 'ethereum', 'bank'
            ],
            targetedBrands: [
                'paypal', 'apple', 'microsoft', 'google', 'facebook', 'amazon',
                'netflix', 'instagram', 'twitter', 'linkedin', 'binance', 'coinbase'
            ],
            obfuscationPatterns: [
                /eval\(.*\)/,
                /\\x[0-9a-f]{2}/i,
                /\\u[0-9a-f]{4}/i,
                /atob\(.*\)/,
                /String\.fromCharCode\(.*\)/,
                /unescape\(.*\)/,
                /^[a-zA-Z0-9+/]{100,}={0,2}$/
            ]
        };

        this.maliciousCodePatterns = [
            {
                pattern: /window\.location\s*=|window\.location\.href\s*=|window\.location\.replace\s*\(/,
                weight: 0.4,
                type: 'Redirection suspecte'
            },
            {
                pattern: /addEventListener\s*\(\s*['"]keyup|keydown|keypress['"]/,
                weight: 0.5,
                type: 'Surveillance du clavier'
            },
            {
                pattern: /debugger|console\.(clear|log)|preventDefault\(\)/,
                weight: 0.3,
                type: 'Anti-débogage'
            }
        ];
    }

    async analyzeContent(url) {
        try {
            const response = await fetch(url);
            const html = await response.text();
            
            const results = {
                obfuscation: this.detectObfuscation(html),
                maliciousCode: this.detectMaliciousCode(html),
                formAnalysis: this.analyzeFormElements(html),
                brandImpersonation: this.detectBrandImpersonation(html, url),
                contentCloaking: this.detectContentCloaking(html),
                suspiciousRedirects: this.detectSuspiciousRedirects(html)
            };

            results.score = this.calculateContentRiskScore(results);
            return results;
        } catch (error) {
            console.error('Content analysis error:', error);
            return null;
        }
    }

    detectObfuscation(html) {
        const obfuscationScore = {
            score: 0,
            detections: []
        };

        this.phishingPatterns.obfuscationPatterns.forEach((pattern, index) => {
            if (pattern.test(html)) {
                obfuscationScore.score += 0.2;
                obfuscationScore.detections.push(
                    `Pattern d'obfuscation #${index + 1} détecté`
                );
            }
        });

        const base64Density = (html.match(/[A-Za-z0-9+/=]{4,}/g) || []).length;
        if (base64Density > 10) {
            obfuscationScore.score += 0.3;
            obfuscationScore.detections.push('Forte présence de code encodé');
        }

        return obfuscationScore;
    }

    detectMaliciousCode(html) {
        const detections = [];
        let score = 0;

        this.maliciousCodePatterns.forEach(({ pattern, weight, type }) => {
            if (pattern.test(html)) {
                score += weight;
                detections.push(type);
            }
        });

        return { score, detections };
    }

    analyzeFormElements(html) {
        const formScore = {
            score: 0,
            detections: []
        };

        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        const forms = doc.getElementsByTagName('form');

        for (const form of forms) {
            const action = form.getAttribute('action');
            if (!action || action === '#' || action.includes('javascript:')) {
                formScore.score += 0.3;
                formScore.detections.push('Formulaire avec destination suspecte');
            }

            const inputs = form.getElementsByTagName('input');
            for (const input of inputs) {
                const inputType = input.getAttribute('type');
                const inputName = input.getAttribute('name');
                const inputId = input.getAttribute('id');

                if (inputType === 'password') {
                    formScore.score += 0.2;
                    formScore.detections.push('Champ de mot de passe détecté');
                }

                if (inputType === 'hidden' && this.containsSensitiveKeyword(inputName || inputId)) {
                    formScore.score += 0.4;
                    formScore.detections.push('Champ sensible masqué détecté');
                }
            }
        }

        return formScore;
    }

    detectBrandImpersonation(html, url) {
        const detections = [];
        let score = 0;
        const domain = new URL(url).hostname;

        this.phishingPatterns.targetedBrands.forEach(brand => {
            if (domain.includes(brand) && !domain.endsWith(`.${brand}.com`)) {
                score += 0.5;
                detections.push(`Imitation possible de ${brand}`);
            }

            const brandRegex = new RegExp(`${brand}.*\\.(png|jpg|gif|svg)`, 'i');
            if (brandRegex.test(html)) {
                score += 0.3;
                detections.push(`Utilisation des ressources de ${brand}`);
            }
        });

        return { score, detections };
    }

    detectContentCloaking(html) {
        const patterns = [
            {
                pattern: /style="[^"]*visibility:\s*hidden|display:\s*none/g,
                weight: 0.3,
                type: 'Contenu masqué par CSS'
            },
            {
                pattern: /<div[^>]*hidden[^>]*>/g,
                weight: 0.3,
                type: 'Élément caché avec attribut hidden'
            },
            {
                pattern: /position:\s*absolute;\s*left:\s*-?\d+px/g,
                weight: 0.4,
                type: 'Contenu positionné hors écran'
            }
        ];

        let score = 0;
        const detections = [];

        patterns.forEach(({ pattern, weight, type }) => {
            if (pattern.test(html)) {
                score += weight;
                detections.push(type);
            }
        });

        return { score, detections };
    }

    detectSuspiciousRedirects(html) {
        const redirectPatterns = [
            {
                pattern: /window\.location\s*=|window\.location\.href\s*=|window\.location\.replace/g,
                weight: 0.4,
                type: 'Redirection JavaScript'
            },
            {
                pattern: /<meta\s+http-equiv="refresh"/g,
                weight: 0.3,
                type: 'Redirection Meta Refresh'
            },
            {
                pattern: /setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*window\.location/g,
                weight: 0.5,
                type: 'Redirection différée'
            }
        ];

        let score = 0;
        const detections = [];

        redirectPatterns.forEach(({ pattern, weight, type }) => {
            if (pattern.test(html)) {
                score += weight;
                detections.push(type);
            }
        });

        return { score, detections };
    }

    containsSensitiveKeyword(text) {
        if (!text) return false;
        return this.phishingPatterns.sensitiveKeywords.some(keyword => 
            text.toLowerCase().includes(keyword)
        );
    }

    calculateContentRiskScore(results) {
        const weights = {
            obfuscation: 0.25,
            maliciousCode: 0.2,
            formAnalysis: 0.2,
            brandImpersonation: 0.15,
            contentCloaking: 0.1,
            suspiciousRedirects: 0.1
        };

        let totalScore = 0;
        for (const [key, weight] of Object.entries(weights)) {
            if (results[key] && typeof results[key].score === 'number') {
                totalScore += results[key].score * weight;
            }
        }

        return Math.min(Math.max(totalScore, 0), 1);
    }
}

// Classe principale pour l'analyse des URLs
class URLAnalyzer {
    constructor() {
        this.cache = new Map();
        this.contentAnalyzer = new ContentAnalyzer();
    }

    async analyzeURL(url) {
        try {
            const cachedResult = this.checkCache(url);
            if (cachedResult) return cachedResult;

            const [
                domainAnalysis,
                virusTotalResult,
                safeBrowsingResult,
                contentAnalysis
            ] = await Promise.all([
                this.analyzeDomain(url),
                this.checkVirusTotal(url),
                this.checkGoogleSafeBrowsing(url),
                this.contentAnalyzer.analyzeContent(url)
            ]);

            const result = {
                timestamp: Date.now(),
                url: url,
                domain: new URL(url).hostname,
                score: this.calculateFinalScore({
                    domain: domainAnalysis,
                    virusTotal: virusTotalResult,
                    safeBrowsing: safeBrowsingResult,
                    content: contentAnalysis
                }),
                details: {
                    domainAnalysis,
                    virusTotalResult,
                    safeBrowsingResult,
                    contentAnalysis
                }
            };

            this.cache.set(url, result);
            return result;

        } catch (error) {
            console.error('Analysis error:', error);
            throw error;
        }
    }

    checkCache(url) {
        if (this.cache.has(url)) {
            const cached = this.cache.get(url);
            if (Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
                return cached;
            }
            this.cache.delete(url);
        }
        return null;
    }

    async analyzeDomain(url) {
        const urlObj = new URL(url);
        const domain = urlObj.hostname;
        const domainParts = domain.split('.');

        return {
            isHttps: urlObj.protocol === 'https:',
            domain: {
                length: domain.length,
                parts: domainParts.length,
                hasSubdomains: domainParts.length > 2
            },
            path: {
                length: urlObj.pathname.length
            },
            score: this.calculateDomainScore(urlObj)
        };
    }

    async checkVirusTotal(url) {
        try {
            const response = await fetch(`${CONFIG.API_ENDPOINTS.VIRUSTOTAL}/report`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    apikey: CONFIG.VIRUSTOTAL_API_KEY,
                    resource: url
                })
            });

            const data = await response.json();
            return {
                positives: data.positives || 0,
                total: data.total || 0,
                scanDate: data.scan_date,
                score: data.positives ? data.positives / data.total : 0
            };
        } catch (error) {
            console.error('VirusTotal API error:', error);
            return null;
        }
    }

    async checkGoogleSafeBrowsing(url) {
        try {
            const response = await fetch(
                `${CONFIG.API_ENDPOINTS.SAFE_BROWSING}?key=${CONFIG.SAFE_BROWSING_API_KEY}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        client: {
                            clientId: "PhishShield",
                            clientVersion: "1.0.0"
                        },
                        threatInfo: {
                            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                            platformTypes: ["ANY_PLATFORM"],
                            threatEntryTypes: ["URL"],
                            threatEntries: [{ url: url }]
                        }
                    })
                }
            );

            const data = await response.json();
            return {
                hasThreats: data.matches && data.matches.length > 0,
                threats: data.matches || [],
                score: data.matches ? Math.min(data.matches.length * 0.5, 1) : 0
            };
        } catch (error) {
            console.error('Safe Browsing API error:', error);
            return null;
        }
    }

    calculateDomainScore(urlObj) {
        let score = 0;

        // Score protocole
        if (!urlObj.protocol.startsWith('https')) score += 0.3;

        // Score sous-domaines
        const subdomains = urlObj.hostname.split('.').length - 2;
        if (subdomains > 0) score += 0.1 * subdomains;

        // Score longueur du chemin
        if (urlObj.pathname.length > 50) score += 0.2;

        // Score paramètres de requête
        if (urlObj.search.length > 0) score += 0.1;

        return Math.min(score, 1);
    }

    calculateFinalScore(results) {
        const weights = {
            domain: 0.2,
            virusTotal: 0.25,
            safeBrowsing: 0.25,
            content: 0.3
        };

        let score = 0;
        
        if (results.domain) {
            score += results.domain.score * weights.domain;
        }
        
        if (results.virusTotal) {
            score += results.virusTotal.score * weights.virusTotal;
        }
        
        if (results.safeBrowsing) {
            score += results.safeBrowsing.score * weights.safeBrowsing;
        }
        
        if (results.content) {
            score += results.content.score * weights.content;
        }

        return Math.min(Math.max(score, 0), 1);
    }
}

// Initialisation de l'analyseur d'URL
const analyzer = new URLAnalyzer();

// Gestionnaire des messages
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'analyzeUrl') {
        analyzer.analyzeURL(request.url)
            .then(result => {
                console.log('Analyse terminée:', result);
                sendResponse(result);
            })
            .catch(error => {
                console.error('Erreur d\'analyse:', error);
                sendResponse({
                    error: true,
                    message: error.message || 'Une erreur est survenue lors de l\'analyse'
                });
            });
        return true; // Indique que la réponse sera asynchrone
    }
});

// Installation du service worker
self.addEventListener('install', (event) => {
    console.log('Service Worker installé');
    self.skipWaiting();
});

// Activation du service worker
self.addEventListener('activate', (event) => {
    console.log('Service Worker activé');
    event.waitUntil(clients.claim());
});