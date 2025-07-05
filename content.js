// content.js
console.log("Phishing Detector content.js loaded.");

// Listen for messages from the popup or background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "get_email_body") {
    console.log("Attempting to get email body...");
    let emailBody = "";
    // Gmail's UI is complex and uses various classes.
    // This attempts to find the main content area of an opened email.
    // You might need to adjust these selectors if Gmail's UI changes.
    // Common selectors for email body:
    // - div[role="listitem"] div[dir="ltr"] (for simple text)
    // - div.nH.pV.pk > div.hK > div.nH.V8.pV.pk > div.nH.pZ > div[tabindex="0"] > div[role="listitem"]
    // - Look for elements with class like "go" or "GS" which often contain the main email content.
    // The most reliable way is often to find the currently visible email's body element.

    // Try to find the currently active email's main content area.
    // This selector targets the readable part of an opened email.
    // This is a common pattern for the "body" of an opened email in Gmail.
    const emailBodyContainer = document.querySelector('div.nH.hx div.nH.If div.nH.hp div.nH.pp div.nH.oy8Mbf:not(.adz) div.ii.gt');

    if (emailBodyContainer) {
        emailBody = emailBodyContainer.innerText; // Get the visible text content
        console.log("Email body found (innerText):", emailBody.substring(0, 200) + "..."); // Log first 200 chars
    } else {
        console.warn("Could not find primary email body container with selector: div.nH.hx div.nH.If div.nH.hp div.nH.pp div.nH.oy8Mbf:not(.adz) div.ii.gt");
        // Fallback for different Gmail views or structures
        // This is a more generic attempt to grab text that looks like email content
        const possibleBodyDivs = document.querySelectorAll('div[role="listitem"] div[dir="ltr"], div[role="article"] div[dir="ltr"]');
        for (const div of possibleBodyDivs) {
            // Heuristic: Check if the div contains significant text and isn't just a header or signature line
            if (div.innerText.length > 50 && !div.closest('[role="toolbar"]') && !div.closest('[aria-label*="Signature"]')) {
                emailBody = div.innerText;
                console.log("Email body found (fallback innerText):", emailBody.substring(0, 200) + "...");
                break;
            }
        }
    }

    if (emailBody) {
      sendResponse({ emailBody: emailBody });
    } else {
      console.warn("No email body found after trying all selectors.");
      sendResponse({ emailBody: null });
    }
    return true; // Indicate that sendResponse will be called asynchronously
  }
});