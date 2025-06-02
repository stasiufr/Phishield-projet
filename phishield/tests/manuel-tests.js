// tests/manual-test.js
document.addEventListener('DOMContentLoaded', () => {
    const testForm = document.getElementById('test-form');
    const resultDiv = document.getElementById('test-results');

    testForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById('url-input');
        const url = urlInput.value;

        try {
            resultDiv.innerHTML = 'Analyse en cours...';
            
            // Appel à l'API de l'extension
            const analysis = await chrome.runtime.sendMessage({
                type: 'analyzeUrl',
                url: url
            });

            // Affichage des résultats
            displayResults(analysis, resultDiv);
        } catch (error) {
            resultDiv.innerHTML = `Erreur: ${error.message}`;
        }
    });
});

function displayResults(analysis, container) {
    container.innerHTML = `
        <h3>Résultats de l'analyse</h3>
        <div class="result-item">
            <strong>Score de risque:</strong> ${analysis.score.toFixed(2)}%
        </div>
        <div class="result-item">
            <strong>Âge du domaine:</strong> ${analysis.details.domainAge} jours
        </div>
        <div class="result-item">
            <strong>Réputation:</strong> ${analysis.details.reputation.score.toFixed(2)}/100
        </div>
        <div class="result-item">
            <strong>Prédiction ML:</strong> ${(analysis.details.mlPrediction * 100).toFixed(2)}%
        </div>
    `;
}