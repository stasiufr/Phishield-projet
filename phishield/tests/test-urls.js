// tests/test-urls.js
const testUrls = {
    legitimate: [
        {
            url: "https://www.amazon.fr",
            expected: {
                risk: "low",
                score: 15
            }
        },
        {
            url: "https://www.google.com",
            expected: {
                risk: "low",
                score: 10
            }
        }
    ],
    suspicious: [
        {
            url: "http://arnaque-banque.example.com",
            expected: {
                risk: "high",
                score: 85
            }
        },
        {
            url: "http://login-paypal.fake-site.com",
            expected: {
                risk: "high",
                score: 90
            }
        }
    ]
};

// Script de test automatisé
async function runTests() {
    console.log("Démarrage des tests...");
    
    for (const category of Object.keys(testUrls)) {
        console.log(`\nTest des URLs ${category}:`);
        
        for (const testCase of testUrls[category]) {
            try {
                const result = await testUrl(testCase.url);
                validateResult(testCase, result);
            } catch (error) {
                console.error(`Erreur lors du test de ${testCase.url}:`, error);
            }
        }
    }
}

async function testUrl(url) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({
            type: 'analyzeUrl',
            url: url
        }, resolve);
    });
}

function validateResult(testCase, result) {
    console.log(`\nTest de ${testCase.url}`);
    console.log(`Score attendu: ${testCase.expected.score}`);
    console.log(`Score obtenu: ${result.score}`);
    
    const scoreThreshold = 5; // Marge d'erreur acceptable
    const isScoreValid = Math.abs(result.score - testCase.expected.score) <= scoreThreshold;
    
    if (isScoreValid) {
        console.log('✅ Test réussi');
    } else {
        console.log('❌ Test échoué');
    }
}

// Exécution des tests
runTests();