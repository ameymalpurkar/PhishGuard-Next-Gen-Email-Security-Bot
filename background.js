// background.js
console.log("Phishing Detector background.js loaded.");

const API_URL = "http://localhost:8000/analyze_text"; // Use full analysis with AI

// Helper function to extract AI analysis from response data
function extractAIAnalysis(responseData) {
  // Check if we have detailed_analysis field (from AI analysis)
  if (responseData.detailed_analysis && responseData.detailed_analysis.trim()) {
    return responseData.detailed_analysis.trim();
  }
  
  // Check if the result text contains AI-specific analysis
  const resultText = responseData.result || '';
  const aiMatch = resultText.match(/🤖 AI Analysis:\s*(.*?)(?=\n📋|\n✅|\n🚨|$)/s);
  if (aiMatch && aiMatch[1].trim()) {
    return aiMatch[1].trim();
  }
  
  // Check for blocked AI analysis messages
  if (resultText.includes('AI analysis was blocked') || resultText.includes('safety filter')) {
    return 'AI analysis was blocked by safety filters. This may indicate high-risk content.';
  }
  
  return 'AI analysis not available - using rule-based detection only';
}

// Helper function to extract technical analysis from response data
function extractTechnicalAnalysis(responseData) {
  let analysis = '';
  
  // Add feature detection results
  if (responseData.features) {
    const detectedFeatures = Object.entries(responseData.features)
      .filter(([feature, detected]) => detected)
      .map(([feature, _]) => feature.replace('has_', '').replace(/_/g, ' '));
    
    if (detectedFeatures.length > 0) {
      analysis += '🔍 Detected Features:\n';
      detectedFeatures.forEach(feature => {
        analysis += `• ${feature.charAt(0).toUpperCase() + feature.slice(1)}\n`;
      });
      analysis += '\n';
    } else {
      analysis += '✅ No suspicious features detected\n\n';
    }
  }
  
  // Add suspicious elements if available
  if (responseData.suspicious_elements) {
    const elements = responseData.suspicious_elements;
    
    if (elements.urls && elements.urls.length > 0) {
      analysis += '🔗 Suspicious URLs:\n';
      elements.urls.forEach(url => {
        analysis += `• ${url}\n`;
      });
      analysis += '\n';
    }
    
    if (elements.urgent_phrases && elements.urgent_phrases.length > 0) {
      analysis += '⚡ Urgent Language:\n';
      elements.urgent_phrases.forEach(phrase => {
        analysis += `• "${phrase}"\n`;
      });
      analysis += '\n';
    }
    
    if (elements.credential_phrases && elements.credential_phrases.length > 0) {
      analysis += '🔑 Credential Requests:\n';
      elements.credential_phrases.forEach(phrase => {
        analysis += `• "${phrase}"\n`;
      });
      analysis += '\n';
    }
    
    if (elements.technical_issues && elements.technical_issues.length > 0) {
      analysis += '⚠️ Technical Issues:\n';
      elements.technical_issues.forEach(issue => {
        analysis += `• ${issue}\n`;
      });
      analysis += '\n';
    }
  }
  
  // Add risk assessment
  const riskLevel = responseData.risk_level || 'unknown';
  const riskScore = responseData.risk_score || 0;
  analysis += `📊 Risk Assessment:\n• Level: ${riskLevel.toUpperCase()}\n• Score: ${(riskScore * 100).toFixed(1)}%`;
  
  return analysis.trim() || 'No technical analysis data available';
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_email") {
    console.log("Received request to analyze email in background script.");
    const emailBody = request.emailBody;

    if (!emailBody) {
      sendResponse({ error: "No email body provided for analysis." });
      return false;
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
            }),
            // Add a timeout to prevent hanging requests
            signal: AbortSignal.timeout(10000) // 10 second timeout
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

          // Structure the response data for the popup
          const structuredData = {
            risk_level: responseData.risk_level,
            risk_score: responseData.risk_score,
            result: responseData.result,
            suspicious_elements: responseData.suspicious_elements || {},
            features: responseData.features || {},
            // Extract sections for display
            ai_analysis: extractAIAnalysis(responseData),
            technical_analysis: extractTechnicalAnalysis(responseData),
            // Add security recommendations if available
            security_recommendations: responseData.security_recommendations || []
          };

          return {
            success: true,
            data: structuredData,
            // Legacy support
            report: responseData.result,
            riskScore: responseData.risk_score,
            riskLevel: responseData.risk_level,
            suspiciousElements: responseData.suspicious_elements || {},
            features: responseData.features || {}
          };
        } catch (error) {
          console.error(`Attempt ${attempt} failed with error:`, error);
          if (error.name === 'AbortError') {
            throw new Error("Request timed out. The server might be unavailable.");
          }
          if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
            throw new Error("Could not connect to API server. Ensure the Python server is running.");
          }
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