// background.js
console.log("Phishing Detector background.js loaded.");

const API_URL = "http://localhost:8000/analyze_text"; // Use full analysis with AI

// Helper function to extract AI analysis from response data
function extractAIAnalysis(responseData) {
  // Check if we have detailed_analysis field (from AI analysis)
  if (responseData.detailed_analysis && responseData.detailed_analysis.trim()) {
    return responseData.detailed_analysis.trim();
  }
  
  // Check features to see if AI analysis was performed
  if (responseData.features && responseData.features.has_ai_analysis) {
    const confidence = responseData.features.ai_confidence || 0;
    const riskLevel = responseData.features.ai_risk_assessment || 'unknown';
    
    let analysis = `AI Risk Assessment: ${riskLevel.toUpperCase()} (${(confidence * 100).toFixed(1)}% confidence)\n\n`;
    
    // Add AI-detected elements
    if (responseData.features.ai_detected_urls > 0) {
      analysis += `🔗 AI detected ${responseData.features.ai_detected_urls} suspicious URL(s)\n`;
    }
    if (responseData.features.ai_detected_urgent_phrases > 0) {
      analysis += `⚠️ AI detected ${responseData.features.ai_detected_urgent_phrases} urgent phrase(s)\n`;
    }
    if (responseData.features.ai_detected_credential_phrases > 0) {
      analysis += `🔑 AI detected ${responseData.features.ai_detected_credential_phrases} credential request(s)\n`;
    }
    
    // Extract AI analysis from result text
    const resultText = responseData.result || '';
    const aiMatch = resultText.match(/🤖 AI Analysis:\s*(.*?)(?=\n📋|$)/s);
    if (aiMatch && aiMatch[1].trim()) {
      analysis += `\n${aiMatch[1].trim()}`;
    }
    
    return analysis;
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
  
  // Check if AI analysis was performed
  if (responseData.features && responseData.features.has_ai_analysis) {
    analysis += '🤖 AI-Powered Technical Analysis:\n';
    analysis += `• Confidence Score: ${(responseData.features.ai_confidence * 100).toFixed(1)}%\n`;
    analysis += `• Risk Assessment: ${responseData.features.ai_risk_assessment.toUpperCase()}\n\n`;
    
    // Add AI-detected features
    const aiFeatures = [];
    if (responseData.features.has_urgency) aiFeatures.push('Urgent/threatening language');
    if (responseData.features.has_suspicious_links) aiFeatures.push('Suspicious URLs');
    if (responseData.features.has_credential_request) aiFeatures.push('Credential requests');
    
    if (aiFeatures.length > 0) {
      analysis += '🔍 AI-Detected Features:\n';
      aiFeatures.forEach(feature => {
        analysis += `• ${feature}\n`;
      });
      analysis += '\n';
    }
  }
  
  // Add rule-based analysis
  if (responseData.features) {
    const ruleFeatures = [];
    if (responseData.features.has_typosquatting) ruleFeatures.push('Domain typosquatting');
    if (responseData.features.has_sender_spoofing) ruleFeatures.push('Sender spoofing');
    if (responseData.features.has_homoglyph_chars) ruleFeatures.push('Homoglyph characters');
    if (responseData.features.has_poor_formatting) ruleFeatures.push('Poor formatting');
    if (responseData.features.has_suspicious_sender) ruleFeatures.push('Suspicious sender patterns');
    
    if (ruleFeatures.length > 0) {
      analysis += '📋 Rule-Based Detection:\n';
      ruleFeatures.forEach(feature => {
        analysis += `• ${feature}\n`;
      });
      analysis += '\n';
    }
  }
  
  // Add suspicious elements if available from AI
  if (responseData.suspicious_elements) {
    const elements = responseData.suspicious_elements;
    
    if (elements.urls && elements.urls.length > 0) {
      analysis += '🔗 Suspicious URLs (AI Detected):\n';
      elements.urls.slice(0, 3).forEach(url => {
        analysis += `• ${url}\n`;
      });
      if (elements.urls.length > 3) {
        analysis += `• ... and ${elements.urls.length - 3} more\n`;
      }
      analysis += '\n';
    }
    
    if (elements.urgent_phrases && elements.urgent_phrases.length > 0) {
      analysis += '⚡ Urgent Language (AI Detected):\n';
      elements.urgent_phrases.slice(0, 3).forEach(phrase => {
        analysis += `• "${phrase}"\n`;
      });
      if (elements.urgent_phrases.length > 3) {
        analysis += `• ... and ${elements.urgent_phrases.length - 3} more\n`;
      }
      analysis += '\n';
    }
    
    if (elements.credential_phrases && elements.credential_phrases.length > 0) {
      analysis += '🔑 Credential Requests (AI Detected):\n';
      elements.credential_phrases.slice(0, 3).forEach(phrase => {
        analysis += `• "${phrase}"\n`;
      });
      if (elements.credential_phrases.length > 3) {
        analysis += `• ... and ${elements.credential_phrases.length - 3} more\n`;
      }
      analysis += '\n';
    }
    
    if (elements.ai_flags && elements.ai_flags.length > 0) {
      analysis += '⚠️ AI System Flags:\n';
      elements.ai_flags.forEach(flag => {
        analysis += `• ${flag}\n`;
      });
      analysis += '\n';
    }
  }
  
  // Add risk assessment summary
  const riskLevel = responseData.risk_level || 'unknown';
  const riskScore = responseData.risk_score || 0;
  analysis += `📊 Final Risk Assessment:\n• Level: ${riskLevel.toUpperCase()}\n• Score: ${(riskScore * 100).toFixed(1)}%`;
  
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