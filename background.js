// background.js
console.log("Phishing Detector background.js loaded.");

const API_URL = "http://localhost:8000/analyze_text"; // Your Python API endpoint

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_email") {
    console.log("Received request to analyze email in background script.");
    const emailBody = request.emailBody;

    if (!emailBody) {
      sendResponse({ error: "No email body provided for analysis." });
      return false; // Indicate that sendResponse is not asynchronous
    }


    fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        text: emailBody
      })
    })
      .then(async response => {
        let data;
        try {
          data = await response.json();
        } catch (e) {
          throw new Error(`Invalid JSON response from server. Status: ${response.status}`);
        }
        if (!response.ok) {
          if (response.status === 404) {
            throw new Error(`API endpoint not found. Make sure your Python server is running on ${API_URL} and the endpoint exists.`);
          } else if (response.status === 500) {
            throw new Error(`Server error (${response.status}): ${response.statusText}. Check your Python server logs.`);
          }
          throw new Error(`HTTP error! Status: ${response.status} - ${response.statusText}`);
        }
        if (data && data.result) {
          sendResponse({ report: data.result });
        } else {
          sendResponse({ error: "Invalid response format from server." });
        }
      })
      .catch(error => {
        console.error("Error during fetch to Python backend:", error);
        sendResponse({ error: `Could not connect to analysis server or server error: ${error.message}. Make sure your Python server is running.` });
      });

    return true; // Indicate that sendResponse will be called asynchronously
  }
});