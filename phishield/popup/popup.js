// État global de l'interface
const UI = {
    elements: {},
    state: {
        isAnalyzing: false,
        currentUrl: '',
        lastAnalysis: null
    }
};

// Initialisation au chargement du document
document.addEventListener('DOMContentLoaded', async () => {
    initializeUI();
    setupEventListeners();
    await startAnalysis();
});

// Initialisation des éléments de l'interface
function initializeUI() {
    UI.elements = {
        currentUrl: document.getElementById('current-url'),
        riskScore: document.getElementById('risk-score'),
        riskLevel: document.getElementById('risk-level'),
        analysisDetails: document.getElementById('analysis-details'),
        statusIndicator: document.getElementById('status-indicator'),
        reportButton: document.getElementById('report-button'),
        settingsButton: document.getElementById('settings-button'),
        virusTotalResults: document.getElementById('virustotal-results'),
        safeBrowsingResults: document.getElementById('safebrowsing-results')
    };
}

// Configuration des écouteurs d'événements
function setupEventListeners() {
    if (UI.elements.reportButton) {
        UI.elements.reportButton.addEventListener('click', handleReportClick);
    }
    if (UI.elements.settingsButton) {
        UI.elements.settingsButton.addEventListener('click', handleSettingsClick);
    }
}

// Démarrage de l'analyse
async function startAnalysis() {
    setLoadingState(true);
    
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        console.log('Current tab:', tab);
        
        if (!tab?.url) {
            throw new Error("Impossible d'accéder à l'URL actuelle");
        }

        updateUrlDisplay(tab.url);
        const analysis = await analyzeUrl(tab.url);
        console.log('Analysis results:', analysis);
        updateUIWithResults(analysis);
    } catch (error) {
        console.error('Analysis error:', error);
        showError(error.message || 'Une erreur est survenue lors de l\'analyse');
    } finally {
        setLoadingState(false);
    }
}

// Analyse de l'URL
async function analyzeUrl(url) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'analyzeUrl', url: url }, (response) => {
            if (chrome.runtime.lastError) {
                reject(chrome.runtime.lastError);
                return;
            }
            if (response?.error) {
                reject(new Error(response.message));
                return;
            }
            resolve(response);
        });
    });
}

// Mise à jour de l'interface avec les résultats
function updateUIWithResults(analysis) {
    if (!analysis) return;

    updateScore(analysis.score);
    updateDetailsSection(analysis.details);
    updateApiResults(analysis.details);
}

// Mise à jour du score
function updateScore(score) {
    const percentage = Math.round(score * 100);
    
    if (UI.elements.riskScore) {
        UI.elements.riskScore.textContent = `${percentage}%`;
        UI.elements.riskScore.className = getRiskClass(percentage);
    }

    if (UI.elements.riskLevel) {
        UI.elements.riskLevel.textContent = getRiskLevel(percentage);
        UI.elements.riskLevel.className = getRiskClass(percentage);
    }
}

// Mise à jour de la section détails
function updateDetailsSection(details) {
    if (!UI.elements.analysisDetails) return;

    const domainAnalysis = details.domainAnalysis;
    UI.elements.analysisDetails.innerHTML = `
        <div class="detail-item">
            <strong>Protocole:</strong> 
            ${domainAnalysis.isHttps ? 
                '<span class="secure">HTTPS (Sécurisé)</span>' : 
                '<span class="warning">HTTP (Non sécurisé)</span>'}
        </div>
        <div class="detail-item">
            <strong>Sous-domaines:</strong> 
            ${domainAnalysis.domain.hasSubdomains ? 'Oui' : 'Non'}
        </div>
        ${generatePatternsHTML(domainAnalysis.domain.suspiciousPatterns)}
    `;
}

// Mise à jour des résultats des APIs
function updateApiResults(details) {
    // Résultats VirusTotal
    if (UI.elements.virusTotalResults && details.virusTotalResult) {
        const vt = details.virusTotalResult;
        UI.elements.virusTotalResults.innerHTML = `
            <h3>VirusTotal</h3>
            <div class="api-result ${getRiskClass(vt.score * 100)}">
                <div>Détections: ${vt.positives}/${vt.total}</div>
                <div>Dernière analyse: ${new Date(vt.scanDate).toLocaleDateString()}</div>
            </div>
        `;
    }

    // Résultats Safe Browsing
    if (UI.elements.safeBrowsingResults && details.safeBrowsingResult) {
        const sb = details.safeBrowsingResult;
        UI.elements.safeBrowsingResults.innerHTML = `
            <h3>Google Safe Browsing</h3>
            <div class="api-result ${sb.hasThreats ? 'risk-high' : 'risk-low'}">
                ${sb.hasThreats ? 
                    `<div>Menaces détectées: ${sb.threats.length}</div>
                     <div>Types: ${sb.threats.map(t => t.threatType).join(', ')}</div>` :
                    '<div>Aucune menace détectée</div>'}
            </div>
        `;
    }
}

// Génération du HTML pour les motifs suspects
function generatePatternsHTML(patterns) {
    if (!patterns || patterns.length === 0) return '';
    
    return `
        <div class="detail-item">
            <strong>Motifs suspects détectés:</strong>
            <ul class="patterns-list">
                ${patterns.map(p => `<li>${p.type} (Impact: ${Math.round(p.weight * 100)}%)</li>`).join('')}
            </ul>
        </div>
    `;
}

// Obtention du niveau de risque
function getRiskLevel(score) {
    if (score >= 70) return "Risque Élevé";
    if (score >= 40) return "Risque Moyen";
    return "Risque Faible";
}

// Obtention de la classe CSS selon le niveau de risque
function getRiskClass(score) {
    if (score >= 70) return 'risk-high';
    if (score >= 40) return 'risk-medium';
    return 'risk-low';
}

// Mise à jour de l'affichage de l'URL
function updateUrlDisplay(url) {
    const domain = new URL(url).hostname;
    UI.state.currentUrl = url;
    if (UI.elements.currentUrl) {
        UI.elements.currentUrl.textContent = domain;
    }
}

// Gestion de l'état de chargement
function setLoadingState(isLoading) {
    UI.state.isAnalyzing = isLoading;
    
    if (UI.elements.statusIndicator) {
        UI.elements.statusIndicator.textContent = isLoading ? 
            'Analyse en cours...' : 'Analyse terminée';
    }
    document.body.classList.toggle('analyzing', isLoading);
}

// Affichage des erreurs
function showError(message) {
    if (UI.elements.analysisDetails) {
        UI.elements.analysisDetails.innerHTML = `
            <div class="error-message">
                Erreur: ${message}
            </div>
        `;
    }
}

// Gestionnaire du bouton de signalement
function handleReportClick() {
    if (!UI.state.currentUrl) return;
    
    // Redirection vers la page de signalement Google
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(UI.state.currentUrl)}`;
    chrome.tabs.create({ url: reportUrl });
}

// Gestionnaire du bouton des paramètres
function handleSettingsClick() {
    chrome.runtime.openOptionsPage();
}