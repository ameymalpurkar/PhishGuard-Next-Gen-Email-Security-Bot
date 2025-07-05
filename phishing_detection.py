#!/usr/bin/env python3
"""
Phishing Detection MCP Server with HTTP Transport

This script implements a microservice using the MCP (Microservice Communication Protocol)
library to detect phishing indicators in text content. It exposes two tools:
'analyze_text' for a detailed report and 'quick_check' for a brief assessment.
It uses HTTP transport for communication, making it suitable for integration
with web applications or browser extensions.
"""

import sys
import re
from urllib.parse import urlparse

# Check if we can import the MCP library and CORS middleware
try:
    from mcp.server.fastmcp import FastMCP
    from fastapi import FastAPI # Import FastAPI directly
    from starlette.middleware.cors import CORSMiddleware
    print("✅ MCP, FastAPI, and Starlette CORS imported successfully", file=sys.stderr)
except ImportError as e:
    print(f"❌ Failed to import necessary libraries: {e}", file=sys.stderr)
    print("Hint: Ensure you have 'mcp[http]' installed. Try: pip install mcp[http] fastapi", file=sys.stderr)
    sys.exit(1)


# --- NEW APPROACH: Create FastAPI app explicitly and add middleware to it ---
# Instead of relying on FastMCP to expose its app, we create the FastAPI app first.
app = FastAPI(title="Phishing Detector API")

# Add CORS middleware directly to the FastAPI app instance.
# This ensures that the 'add_middleware' method is called on a FastAPI app object.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",      # Allow requests from your local Python server
        "https://mail.google.com",    # Allow requests from Gmail (where your content script runs)
        # For a deployed Chrome extension, you would also need to add its specific origin:
        # "chrome-extension://YOUR_EXTENSION_ID" # Replace YOUR_EXTENSION_ID with your actual extension ID
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers in the request
)

# Initialize the MCP server instance, passing our pre-configured FastAPI app
mcp = FastMCP("phishing-detector", app=app) # Pass the FastAPI app to FastMCP


# --- Core Phishing Detection Logic ---
def extract_features(text: str) -> dict:
    """
    Extracts various features from the input text that can indicate phishing attempts.

    Args:
        text (str): The text content (e.g., email body) to analyze.

    Returns:
        dict: A dictionary where keys are feature names and values are booleans
              indicating if the feature is present (True) or not (False).
    """
    features = {
        'has_urgency': False,
        'has_suspicious_links': False,
        'has_credential_request': False,
        'has_suspicious_sender': False, # This is a conceptual check for text content
        'has_poor_formatting': False
    }
    # Convert text to lowercase for case-insensitive matching
    text_lower = text.lower()

    # 1. Check for urgency-related keywords
    urgency_words = [
        'urgent', 'immediate', 'action required', 'account suspended',
        'security alert', 'unauthorized', 'verify your account',
        'expire', 'limited time', 'click now'
    ]
    features['has_urgency'] = any(word in text_lower for word in urgency_words)

    # 2. Check for suspicious links (TLDs, IP addresses, uncommon ports)
    # Regex to find URLs (http or https)
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    # List of commonly abused or free domain extensions
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.online', '.site', '.top', '.bid']

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # Check if domain ends with a suspicious TLD
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                features['has_suspicious_links'] = True
                break # Found one, no need to check further

            # Check for IP addresses in the hostname (e.g., http://192.168.1.1/login)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                features['has_suspicious_links'] = True
                break

            # Check for uncommon ports (e.g., http://example.com:8080)
            if parsed.port is not None and parsed.port not in [80, 443]:
                features['has_suspicious_links'] = True
                break

        except Exception:
            # If URL parsing fails, it might be a malformed/obfuscated link, consider it suspicious
            features['has_suspicious_links'] = True
            break
    
    # 3. Check for credential request keywords
    credential_words = [
        'password', 'login', 'credential', 'verify', 'bank account',
        'credit card', 'social security', 'ssn', 'account details',
        'update payment', 'confirm identity', 'reset password', 'security code'
    ]
    features['has_credential_request'] = any(word in text_lower for word in credential_words)

    # 4. Check for suspicious sender patterns (based on text content, not actual email headers)
    # This is a heuristic. For true sender analysis, you'd need the 'From:' header.
    suspicious_patterns = [
        r'@.*\.(tk|ml|ga|cf|gq|xyz|online|site|top|bid)$', # Free/suspicious TLDs in apparent sender addresses
        r'support.*@(?!yourcompany\.com)', # Generic support email not from expected domain
        r'security.*@(?!yourcompany\.com)',
        r'admin.*@(?!yourcompany\.com)',
        r'noreply.*@(?!yourcompany\.com)'
    ]
    # Note: Replace 'yourcompany.com' with actual legitimate domains if known.
    features['has_suspicious_sender'] = any(re.search(pattern, text_lower) for pattern in suspicious_patterns)

    # 5. Check for poor formatting indicators
    features['has_poor_formatting'] = (
        text.count('!') > 3 or                       # Excessive exclamation marks
        text.count('$') > 2 or                       # Excessive currency symbols
        len(re.findall(r'[A-Z]{4,}', text)) > 2 or   # Excessive use of ALL CAPS words (4 or more consecutive uppercase)
        ('click here' in text_lower and not urls) or # Call to action without a clear link
        ('kindly' in text_lower and text_lower.count('kindly') > 1) # Overuse of "kindly"
    )
    return features


# --- MCP Tool Definitions ---

@mcp.tool()
async def analyze_links(text: str) -> str:
    """
    Analyzes all links found in the given text for potential phishing risk.

    Args:
        text (str): The email or message text to scan for links.

    Returns:
        str: A report detailing the phishing risk for each identified link.
    """
    # Find all URLs in the text
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    if not urls:
        return "No links found in the provided text."

    # List of commonly suspicious or free domain extensions
    suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.online', '.site', '.top', '.bid']
    
    report = ["🔗 Link Analysis Report 🔗\n"]

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            is_suspicious_domain = any(domain.endswith(susp) or susp in domain for susp in suspicious_domains)
            is_ip_address_domain = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)
            has_uncommon_port = parsed.port is not None and parsed.port not in [80, 443]

            if is_suspicious_domain or is_ip_address_domain or has_uncommon_port:
                report.append(f"🚨 Suspicious link: {url}")
            else:
                report.append(f"✅ Safe-looking link: {url}")
        except Exception as e:
            report.append(f"⚠️ Could not analyze link: {url} (Error: {e})")
    return "\n".join(report)


@mcp.tool()
async def analyze_text(text: str) -> str:
    """
    Analyzes text content for a comprehensive set of potential phishing indicators
    and provides a detailed report with a risk score and level.

    Args:
        text (str): The text content to analyze for phishing.

    Returns:
        str: A detailed analysis report including risk score, detected features,
             and an overall risk level.
    """
    features = extract_features(text)

    # Assign weights to each feature to calculate a weighted risk score
    feature_weights = {
        'has_urgency': 0.20,
        'has_suspicious_links': 0.30,
        'has_credential_request': 0.25,
        'has_suspicious_sender': 0.15,
        'has_poor_formatting': 0.10
    }

    # Calculate the total risk score based on present features and their weights
    risk_score = sum(feature_weights[feature] for feature, present in features.items() if present)

    report = ["📧 Phishing Analysis Report 📧\n"]
    report.append(f"Overall Risk Score: {risk_score:.2f}/1.00")
    report.append("\n--- Detected Features ---")

    # List all features and whether they were detected
    for feature, present in features.items():
        emoji = "🚨" if present else "✅"
        # Format feature name for readability (e.g., "has_urgency" -> "Has Urgency")
        feature_name = feature.replace('_', ' ').title()
        report.append(f"{emoji} {feature_name}: {'Yes' if present else 'No'}")

    # Determine the overall risk level based on the risk score
    if risk_score >= 0.7:
        risk_level = "⚠️ HIGH RISK - This message shows strong indicators of being a phishing attempt."
    elif risk_score >= 0.4:
        risk_level = "⚠️ MEDIUM RISK - This message shows some suspicious characteristics."
    else:
        risk_level = "✅ LOW RISK - This message shows few or no suspicious characteristics."

    report.append(f"\n--- Risk Level ---")
    report.append(f"{risk_level}")
    return "\n".join(report)


@mcp.tool()
async def quick_check(text: str) -> str:
    """
    Provides a quick assessment of whether a text is likely to be a phishing attempt.
    This tool gives a brief, summary-level result.

    Args:
        text (str): The text content to quickly check for phishing.

    Returns:
        str: A brief summary of the phishing likelihood.
    """
    features = extract_features(text)

    # Count the number of suspicious features detected
    num_suspicious_features = sum(1 for present in features.values() if present)

    # Provide a brief assessment based on the number of suspicious features
    if num_suspicious_features >= 3:
        return "🚨 High likelihood of phishing! Exercise extreme caution and do not interact."
    elif num_suspicious_features >= 1:
        return "⚠️ Some suspicious elements detected. Review carefully before proceeding."
    else:
        return "✅ Low risk - few or no suspicious elements detected."


# --- Server Execution ---
if __name__ == "__main__":
    # Define the port for the HTTP server.
    # Ensure this port is not in use by another application.
    SERVER_PORT = 8000

    print(f"🚀 Starting Phishing Detection MCP server on http://localhost:{SERVER_PORT}...", file=sys.stderr)
    print("📡 Available tools: analyze_text, quick_check, analyze_links", file=sys.stderr)
    print("💡 To stop the server, press Ctrl+C", file=sys.stderr)

    try:
        # Run the MCP server using the HTTP transport on the specified port.
        # This will start a Uvicorn server in the background.
        mcp.run(transport='http', port=SERVER_PORT)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user (KeyboardInterrupt)", file=sys.stderr)
    except Exception as e:
        print(f"💥 Server error: {e}", file=sys.stderr)
        sys.exit(1)
