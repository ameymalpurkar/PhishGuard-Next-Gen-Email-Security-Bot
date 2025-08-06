// background.js
console.log("Phishing Detector background.js loaded.");

const API_URL = "http://localhost:8000/quick_check"; // Primary analysis endpoint

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_email") {
    console.log("Received request to analyze email in background script.");
    const emailBody = request.emailBody;

    if (!emailBody) {
      sendResponse({ error: "No email body provided for analysis." });
      return false; // Indicate that sendResponse is not asynchronous
    }


    // Analyze the email with retry capability
    async function analyzeWithRetry(retryCount = 3, delay = 1000) {
      for (let attempt = 1; attempt <= retryCount; attempt++) {
        try {
          console.log(`Attempt ${attempt} of ${retryCount}`);
          
          const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify({
              text: emailBody
            })
          });

          // Get raw text first for better error handling
          const textData = await response.text();
          console.log(`Response (Attempt ${attempt}):`, textData);
          
          let responseData;
          try {
            responseData = JSON.parse(textData);
          } catch (parseError) {
            if (attempt < retryCount) {
              console.log(`JSON parse failed, retrying...`);
              await new Promise(resolve => setTimeout(resolve, delay));
              continue;
            }
            throw new Error(`Invalid JSON response: ${textData.substring(0, 100)}...`);
          }

          if (!response.ok) {
            if (response.status === 500 && attempt < retryCount) {
              console.log(`Server error, retrying in ${delay}ms...`);
              await new Promise(resolve => setTimeout(resolve, delay));
              continue;
            }
            throw new Error(`HTTP ${response.status}: ${textData}`);
          }

          return {
            report: responseData.result,
            riskScore: responseData.risk_score,
            riskLevel: responseData.risk_level,
            suspiciousElements: responseData.suspicious_elements || {},
            features: responseData.features || {
              has_urgency: false,
              has_suspicious_links: false,
              has_credential_request: false,
              has_suspicious_sender: false,
              has_poor_formatting: false,
              has_typosquatting: false
            }
          };
        } catch (error) {
          if (attempt === retryCount) throw error;
          console.error(`Attempt ${attempt} failed:`, error);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    // Execute the analysis with retry
    analyzeWithRetry()
      .then(result => sendResponse(result))
      .catch(error => {
        console.error("Analysis failed:", error);
        sendResponse({ 
          error: `Analysis failed: ${error.message}. Please try again.`,
          errorDetails: error.toString()
        });
      });

    return true; // Indicate that sendResponse will be called asynchronously
  }
});