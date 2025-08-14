// Toggle section visibility
function toggleSection(sectionName) {
  const content = document.getElementById(`${sectionName}Content`);
  const toggle = document.getElementById(`${sectionName}Toggle`);
  
  if (content.classList.contains('collapsed')) {
    content.classList.remove('collapsed');
    toggle.textContent = '▼';
    toggle.classList.remove('collapsed');
  } else {
    content.classList.add('collapsed');
    toggle.textContent = '▶';
    toggle.classList.add('collapsed');
  }
}

// Display analysis results in separate sections
function displayAnalysis(analysisResult) {
  console.log('Displaying analysis:', analysisResult);
  
  // Handle both new structured format and legacy formats
  let data;
  if (analysisResult && analysisResult.data) {
    data = analysisResult.data;
  } else if (typeof analysisResult === 'object' && analysisResult.risk_level) {
    data = analysisResult;
  } else {
    // Fall back to legacy text format
    displayLegacyAnalysis(analysisResult);
    return;
  }

  // Show analysis sections
  document.getElementById('summarySection').style.display = 'block';
  document.getElementById('aiSection').style.display = 'block';
  document.getElementById('ruleSection').style.display = 'block';

  // Summary Section
  displaySummarySection(data);
  
  // AI Analysis Section
  displayAISection(data);
  
  // Technical Analysis Section  
  displayTechnicalSection(data);
}

function displaySummarySection(data) {
  const summaryContent = document.getElementById('summaryContent');
  const riskLevel = data.risk_level || 'unknown';
  const riskScore = data.risk_score || 0;
  const riskEmoji = riskLevel === 'high' ? '🚨' : riskLevel === 'medium' ? '⚠️' : '✅';
  
  // Get the main message from the result
  let mainMessage = 'Analysis completed';
  if (data.result) {
    const lines = data.result.split('\n');
    mainMessage = lines[0].replace(/[🚨⚠️✅]/g, '').trim();
  }
  
  summaryContent.innerHTML = `<div style="font-size: 1.1em; margin-bottom: 10px;">
    ${riskEmoji} <strong>Risk Level:</strong> ${riskLevel.toUpperCase()}
  </div>
  <div style="margin-bottom: 10px;">
    <strong>Confidence Score:</strong> ${(riskScore * 100).toFixed(1)}%
  </div>
  <div style="padding: 8px; background-color: ${riskLevel === 'high' ? '#ffebee' : riskLevel === 'medium' ? '#fff3e0' : '#e8f5e8'}; border-radius: 4px;">
    <strong>Assessment:</strong><br>${mainMessage}
  </div>`;
}

function displayAISection(data) {
  const aiContent = document.getElementById('aiContent');
  
  if (data.ai_analysis && data.ai_analysis !== 'AI analysis not available - using rule-based detection only') {
    aiContent.textContent = data.ai_analysis;
  } else {
    aiContent.innerHTML = `<div style="color: #666; font-style: italic;">
      AI analysis is currently using rule-based detection only.<br>
      <small>This provides reliable phishing detection based on known patterns and indicators.</small>
    </div>`;
  }
  
  // Add security recommendations if available
  if (data.security_recommendations && data.security_recommendations.length > 0) {
    aiContent.innerHTML += `<br><br><strong>�️ Security Recommendations:</strong><br>`;
    data.security_recommendations.forEach(rec => {
      aiContent.innerHTML += `• ${rec}<br>`;
    });
  }
}

function displayTechnicalSection(data) {
  const ruleContent = document.getElementById('ruleContent');
  
  if (data.technical_analysis) {
    ruleContent.textContent = data.technical_analysis;
  } else {
    // Fallback: build technical analysis from available data
    let analysis = '';
    
    if (data.features) {
      const detectedFeatures = Object.entries(data.features)
        .filter(([feature, detected]) => detected)
        .map(([feature, _]) => feature.replace('has_', '').replace(/_/g, ' '));
      
      if (detectedFeatures.length > 0) {
        analysis += '� Detected Features:\n';
        detectedFeatures.forEach(feature => {
          analysis += `• ${feature.charAt(0).toUpperCase() + feature.slice(1)}\n`;
        });
      } else {
        analysis += '✅ No suspicious features detected';
      }
    }
    
    ruleContent.textContent = analysis || 'Technical analysis completed';
  }
}

// Fallback for legacy analysis format
function displayLegacyAnalysis(analysisText) {
  document.getElementById('summarySection').style.display = 'block';
  document.getElementById('summaryContent').textContent = analysisText;
  
  // Hide other sections if no structured data
  document.getElementById('aiSection').style.display = 'none';
  document.getElementById('ruleSection').style.display = 'none';
}

// Show loading state
function showLoading(message) {
  const statusDiv = document.getElementById('status');
  statusDiv.innerHTML = `<span class="loading-spinner"></span>${message}`;
}

// Show error state
function showError(message) {
  const statusDiv = document.getElementById('status');
  statusDiv.innerHTML = `<span class="error">❌ ${message}</span>`;
}

// Show success state
function showSuccess(message) {
  const statusDiv = document.getElementById('status');
  statusDiv.innerHTML = `<span class="success">✅ ${message}</span>`;
}

document.addEventListener('DOMContentLoaded', () => {
  const analyzeButton = document.getElementById('analyzeButton');

  analyzeButton.addEventListener('click', async () => {
    showLoading('Scanning email...');
    
    // Hide previous results
    document.getElementById('summarySection').style.display = 'none';
    document.getElementById('aiSection').style.display = 'none';
    document.getElementById('ruleSection').style.display = 'none';
    
    analyzeButton.disabled = true;

    // Get the active tab
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab && tab.url.startsWith('https://mail.google.com')) {
      // Send a message to the content script to get the email body
      chrome.tabs.sendMessage(tab.id, { action: "get_email_body" }, (response) => {
        if (chrome.runtime.lastError) {
          showError('Could not communicate with Gmail tab. Make sure an email is open.');
          analyzeButton.disabled = false;
          return;
        }

        if (response && response.emailBody) {
          showLoading('Email content extracted. Analyzing with AI and rule-based detection...');
          
          // Send the email body to the background script
          chrome.runtime.sendMessage({ action: "analyze_email", emailBody: response.emailBody }, (analysisResponse) => {
            if (chrome.runtime.lastError) {
              console.error("Error sending message to background:", chrome.runtime.lastError.message);
              showError('Communication failed with background script.');
              analyzeButton.disabled = false;
              return;
            }
            
            console.log('Received analysis response:', analysisResponse);
            
            if (analysisResponse && analysisResponse.success && analysisResponse.data) {
              showSuccess('Analysis complete!');
              displayAnalysis(analysisResponse);
            } else if (analysisResponse && (analysisResponse.report || analysisResponse.data)) {
              // Handle legacy format
              showSuccess('Analysis complete!');
              displayAnalysis(analysisResponse.data || analysisResponse);
            } else if (analysisResponse && analysisResponse.error) {
              showError(`Analysis failed: ${analysisResponse.error}`);
              console.error('Analysis error details:', analysisResponse.errorDetails);
            } else {
              showError('No analysis report received.');
              console.error('Unexpected response format:', analysisResponse);
            }
            analyzeButton.disabled = false;
          });
        } else {
          showError('Could not extract email body. Make sure an email is open in Gmail.');
          analyzeButton.disabled = false;
        }
      });
    } else {
      showError('Please navigate to a Gmail email to use this tool.');
      analyzeButton.disabled = false;
    }
  });
});