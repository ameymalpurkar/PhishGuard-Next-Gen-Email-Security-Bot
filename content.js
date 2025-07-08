// content.js
console.log("Phishing Detector content.js loaded.");

// Listen for messages from the popup or background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "get_email_body") {
    console.log("Attempting to get email body...");
    let emailBody = "";

    // Try multiple selectors in order of specificity to generality
    const selectors = [
      // Most specific (current Gmail structure)
      'div.nH.hx div.nH.If div.nH.hp div.nH.pp div.nH.oy8Mbf:not(.adz) div.ii.gt',
      // Common Gmail body containers
      'div.a3s.aXjCH',
      'div.ii.gt',
      // Fallbacks
      'div[role="listitem"] div[dir="ltr"]',
      'div[role="article"] div[dir="ltr"]',
      'div.gs',
      'div.go',
    ];

    for (const selector of selectors) {
      const el = document.querySelector(selector);
      if (el && el.innerText && el.innerText.length > 50) {
        emailBody = el.innerText;
        console.log(`Email body found with selector '${selector}':`, emailBody.substring(0, 200) + "...");
        break;
      }
    }

    // If still not found, try to find the largest visible text block
    if (!emailBody) {
      let maxLen = 0;
      let bestDiv = null;
      const allDivs = document.querySelectorAll('div');
      for (const div of allDivs) {
        if (div.offsetParent !== null && div.innerText && div.innerText.length > maxLen && div.innerText.length > 50) {
          // Exclude toolbars, signatures, and hidden elements
          if (!div.closest('[role="toolbar"]') && !div.closest('[aria-label*="Signature"]')) {
            maxLen = div.innerText.length;
            bestDiv = div;
          }
        }
      }
      if (bestDiv) {
        emailBody = bestDiv.innerText;
        console.log("Email body found (largest visible block):", emailBody.substring(0, 200) + "...");
      }
    }

    if (emailBody) {
      sendResponse({ emailBody: emailBody });
    } else {
      console.warn("No email body found after trying all selectors and fallbacks.");
      sendResponse({ emailBody: null });
    }
    return true; // Indicate that sendResponse will be called asynchronously
  }
});