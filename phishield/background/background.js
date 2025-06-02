import * as tf from '../lib/tensorflow/tf.min.js';
import { extractFeatures } from '../utils/helpers.js';

class PhishingDetector {
    constructor() {
        this.model = null;
        this.cache = new Map();
        this.initializeModel();
    }

    async initializeModel() {
        try {
            this.model = await tf.loadLayersModel('../models/phishing-model/model.json');
            console.log('Modèle ML chargé avec succès');
        } catch (error) {
            console.error('Erreur de chargement du modèle:', error);
        }
    }

    async analyzeDomain(url) {
        if (this.cache.has(url)) {
            return this.cache.get(url);
        }

        try {
            const domain = new URL(url).hostname;

            if (!this.model) {
                return this.basicAnalysis(domain);
            }

            const features = await this.extractFeatures(url);
            const prediction = await this.runMLPrediction(features);
            
            const analysis = {
                timestamp: Date.now(),
                score: prediction,
                details: {
                    domain: domain,
                    features: features,
                    mlPrediction: prediction
                }
            };

            this.cache.set(url, analysis);
            setTimeout(() => this.cache.delete(url), 5 * 60 * 1000);

            return analysis;

        } catch (error) {
            console.error('Erreur lors de l\'analyse:', error);
            return {
                error: true,
                message: error.message
            };
        }
    }

    async extractFeatures(url) {
        return {
            domainLength: new URL(url).hostname.length,
            hasHTTPS: url.startsWith('https'),
        };
    }

    async runMLPrediction(features) {
        try {
            const tensorFeatures = tf.tensor2d([Object.values(features)]);
            const prediction = await this.model.predict(tensorFeatures);
            const score = (await prediction.data())[0];
            tensorFeatures.dispose();
            prediction.dispose();
            return score;
        } catch (error) {
            console.error('Erreur prédiction ML:', error);
            return 0.5; 
        }
    }

    basicAnalysis(domain) {
        return {
            timestamp: Date.now(),
            score: 0.5,
            details: {
                domain: domain,
                message: "Analyse ML non disponible"
            }
        };
    }
}

const detector = new PhishingDetector();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'analyzeUrl') {
        detector.analyzeDomain(request.url)
            .then(sendResponse)
            .catch(error => sendResponse({ error: true, message: error.message }));
        return true;
    }
});

const rules = [{
    id: 1,
    priority: 1,
    action: {
        type: 'block'
    },
    condition: {
        urlFilter: '*phishing*',
        resourceTypes: ['main_frame']
    }
}];

chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: rules.map(rule => rule.id),
    addRules: rules
});
