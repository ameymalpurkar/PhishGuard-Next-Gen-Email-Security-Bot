document.addEventListener('DOMContentLoaded', () => {
  const analyzeButton = document.getElementById('analyzeButton');
  const statusDiv = document.getElementById('status');
  const resultDiv = document.getElementById('result');

  analyzeButton.addEventListener('click', async () => {
    statusDiv.textContent = 'Scanning email...';
    resultDiv.textContent = '';
    analyzeButton.disabled = true;

    // Get the active tab
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab && tab.url.startsWith('https://mail.google.com')) {
      // Send a message to the content script to get the email body
      chrome.tabs.sendMessage(tab.id, { action: "get_email_body" }, (response) => {
        if (chrome.runtime.lastError) {
          // console.error("Error sending message:", chrome.runtime.lastError.message);
          statusDiv.textContent = 'Error: Could not communicate with Gmail tab. Make sure an email is open.';
          analyzeButton.disabled = false;
          return;
        }

        if (response && response.emailBody) {
          statusDiv.textContent = 'Email content extracted. Sending to analyzer...';
          // Send the email body to the background script
          chrome.runtime.sendMessage({ action: "analyze_email", emailBody: response.emailBody }, (analysisResponse) => {
            if (chrome.runtime.lastError) {
              console.error("Error sending message to background:", chrome.runtime.lastError.message);
              statusDiv.textContent = 'Error during analysis: Communication failed with background script.';
              analyzeButton.disabled = false;
              return;
            }
            if (analysisResponse && analysisResponse.report) {
              statusDiv.textContent = 'Analysis complete.';
              resultDiv.textContent = analysisResponse.report;
            } else if (analysisResponse && analysisResponse.error) {
              statusDiv.textContent = `Analysis error: ${analysisResponse.error}`;
              resultDiv.textContent = '';
            } else {
              statusDiv.textContent = 'No analysis report received.';
              resultDiv.textContent = '';
            }
            analyzeButton.disabled = false;
          });
        } else {
          statusDiv.textContent = 'Could not extract email body. Make sure an email is open in Gmail.';
          analyzeButton.disabled = false;
        }
      });
    } else {
      statusDiv.textContent = 'Please navigate to a Gmail email to use this tool.';
      analyzeButton.disabled = false;
    }
  });
});