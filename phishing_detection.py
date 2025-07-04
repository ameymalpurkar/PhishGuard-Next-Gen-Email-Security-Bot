def analyze_links(text: str) -> str:
    """
    Analyze all links in the given text for phishing risk.
    Args:
        text (str): The email or message text
    Returns:
        str: Report on each link's phishing risk
    """
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    if not urls:
        return "No links found in the provided text."
    suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq']
    report = ["🔗 Link Analysis Report 🔗\n"]
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if any(domain.endswith(susp) or susp in domain for susp in suspicious_domains):
                report.append(f"🚨 Suspicious link: {url}")
            else:
                report.append(f"✅ Safe-looking link: {url}")
        except Exception as e:
            report.append(f"⚠️ Could not analyze link: {url} ({e})")
    return "\n".join(report)
#!/usr/bin/env python3
"""
Phishing Detection MCP Server
"""

import sys

import re
from urllib.parse import urlparse

# Check if we can import the MCP library
try:
    from mcp.server.fastmcp import FastMCP
    print("✅ MCP imported successfully", file=sys.stderr)
except ImportError as e:
    print(f"❌ Failed to import MCP: {e}", file=sys.stderr)
    print("Try: pip install mcp", file=sys.stderr)
    sys.exit(1)


# Initialize server
mcp = FastMCP("phishing-detector")


# --- Phishing Detection Logic ---
def extract_features(text: str):
    """Extract features from the text for phishing detection."""
    features = {
        'has_urgency': False,
        'has_suspicious_links': False,
        'has_credential_request': False,
        'has_suspicious_sender': False,
        'has_poor_formatting': False
    }
    text = text.lower()
    urgency_words = ['urgent', 'immediate', 'action required', 'account suspended',
                    'security alert', 'unauthorized', 'verify your account']
    features['has_urgency'] = any(word in text for word in urgency_words)
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    for url in urls:
        try:
            parsed = urlparse(url)
            if any(suspicious in parsed.netloc for suspicious in ['.tk', '.ml', '.ga', '.cf', '.gq']):
                features['has_suspicious_links'] = True
        except:
            features['has_suspicious_links'] = True
    credential_words = ['password', 'login', 'credential', 'verify', 'bank account',
                       'credit card', 'social security', 'ssn']
    features['has_credential_request'] = any(word in text for word in credential_words)
    suspicious_patterns = [
        r'@.*\.(tk|ml|ga|cf|gq)$',
        r'support.*@(?!company\.com)',
        r'security.*@(?!company\.com)',
        r'admin.*@(?!company\.com)'
    ]
    features['has_suspicious_sender'] = any(re.search(pattern, text) for pattern in suspicious_patterns)
    features['has_poor_formatting'] = (
        text.count('!') > 3 or
        text.count('$') > 2 or
        len(re.findall(r'[A-Z]{4,}', text)) > 2
    )
    return features

@mcp.tool()
async def analyze_text(text: str) -> str:
    """
    Analyze text for potential phishing indicators.
    Args:
        text (str): The text to analyze for phishing content
    Returns:
        str: Analysis report with phishing likelihood and detected features
    """
    features = extract_features(text)
    feature_weights = {
        'has_urgency': 0.2,
        'has_suspicious_links': 0.3,
        'has_credential_request': 0.25,
        'has_suspicious_sender': 0.15,
        'has_poor_formatting': 0.1
    }
    risk_score = sum(feature_weights[feature] for feature, present in features.items() if present)
    report = ["📧 Phishing Analysis Report 📧\n"]
    report.append(f"Risk Score: {risk_score:.2f}/1.0")
    report.append("\nDetected Features:")
    for feature, present in features.items():
        emoji = "🚨" if present else "✅"
        feature_name = feature.replace('_', ' ').title()
        report.append(f"{emoji} {feature_name}: {'Yes' if present else 'No'}")
    if risk_score >= 0.7:
        risk_level = "⚠️ HIGH RISK - This message shows strong indicators of being a phishing attempt"
    elif risk_score >= 0.4:
        risk_level = "⚠️ MEDIUM RISK - This message shows some suspicious characteristics"
    else:
        risk_level = "✅ LOW RISK - This message shows few or no suspicious characteristics"
    report.append(f"\nRisk Level: {risk_level}")
    return "\n".join(report)

@mcp.tool()
async def quick_check(text: str) -> str:
    """
    Quickly check if a text is likely to be a phishing attempt.
    Args:
        text (str): The text to check
    Returns:
        str: Brief analysis result
    """
    features = extract_features(text)
    risk_score = sum(1 for present in features.values() if present) / len(features)
    if risk_score >= 0.6:
        return "🚨 High likelihood of phishing! Exercise caution!"
    elif risk_score >= 0.3:
        return "⚠️ Some suspicious elements detected. Review carefully."
    else:
        return "✅ Low risk - few or no suspicious elements detected."


if __name__ == "__main__":
    print("🚀 Starting Phishing Detection MCP server...", file=sys.stderr)
    print("📡 Available tools: analyze_text, quick_check", file=sys.stderr)
    try:
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user", file=sys.stderr)
    except Exception as e:
        print(f"💥 Server error: {e}", file=sys.stderr)
        sys.exit(1)