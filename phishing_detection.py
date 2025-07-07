#!/usr/bin/env python3
"""
Phishing Detection API Server with FastAPI

This script implements a REST API using FastAPI to detect phishing indicators 
in text content. It exposes three endpoints for phishing analysis.
"""

import sys
import re
from urllib.parse import urlparse
from typing import Dict, Any

# Check if we can import the necessary libraries
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
    print("✅ FastAPI and dependencies imported successfully", file=sys.stderr)
except ImportError as e:
    print(f"❌ Failed to import necessary libraries: {e}", file=sys.stderr)
    print("Hint: Install required packages with: pip install fastapi uvicorn", file=sys.stderr)
    sys.exit(1)


# --- Pydantic Models for Request/Response ---
class TextAnalysisRequest(BaseModel):
    text: str

class AnalysisResponse(BaseModel):
    result: str
    risk_score: float = None
    risk_level: str = None


# --- Create FastAPI app ---
app = FastAPI(
    title="Phishing Detector API",
    description="API for detecting phishing indicators in text content",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://localhost:3000",
        "https://mail.google.com",
        "chrome-extension://*",  # Allow Chrome extensions
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Core Phishing Detection Logic ---
def extract_features(text: str) -> Dict[str, bool]:
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
        'has_suspicious_sender': False,
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
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.online', '.site', '.top', '.bid']

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # Check if domain ends with a suspicious TLD
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                features['has_suspicious_links'] = True
                break

            # Check for IP addresses in the hostname
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                features['has_suspicious_links'] = True
                break

            # Check for uncommon ports
            if parsed.port is not None and parsed.port not in [80, 443]:
                features['has_suspicious_links'] = True
                break

        except Exception:
            features['has_suspicious_links'] = True
            break
    
    # 3. Check for credential request keywords
    credential_words = [
        'password', 'login', 'credential', 'verify', 'bank account',
        'credit card', 'social security', 'ssn', 'account details',
        'update payment', 'confirm identity', 'reset password', 'security code'
    ]
    features['has_credential_request'] = any(word in text_lower for word in credential_words)

    # 4. Check for suspicious sender patterns
    suspicious_patterns = [
        r'@.*\.(tk|ml|ga|cf|gq|xyz|online|site|top|bid)$',
        r'support.*@(?!yourcompany\.com)',
        r'security.*@(?!yourcompany\.com)',
        r'admin.*@(?!yourcompany\.com)',
        r'noreply.*@(?!yourcompany\.com)'
    ]
    features['has_suspicious_sender'] = any(re.search(pattern, text_lower) for pattern in suspicious_patterns)

    # 5. Check for poor formatting indicators
    features['has_poor_formatting'] = (
        text.count('!') > 3 or
        text.count('$') > 2 or
        len(re.findall(r'[A-Z]{4,}', text)) > 2 or
        ('click here' in text_lower and not urls) or
        ('kindly' in text_lower and text_lower.count('kindly') > 1)
    )
    
    return features


def calculate_risk_score(features: Dict[str, bool]) -> float:
    """Calculate weighted risk score based on detected features."""
    feature_weights = {
        'has_urgency': 0.20,
        'has_suspicious_links': 0.30,
        'has_credential_request': 0.25,
        'has_suspicious_sender': 0.15,
        'has_poor_formatting': 0.10
    }
    
    return sum(feature_weights[feature] for feature, present in features.items() if present)


def get_risk_level(risk_score: float) -> str:
    """Determine risk level based on risk score."""
    if risk_score >= 0.7:
        return "HIGH RISK - This message shows strong indicators of being a phishing attempt."
    elif risk_score >= 0.4:
        return "MEDIUM RISK - This message shows some suspicious characteristics."
    else:
        return "LOW RISK - This message shows few or no suspicious characteristics."


# --- API Endpoints ---

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Phishing Detection API",
        "version": "1.0.0",
        "endpoints": {
            "analyze_text": "POST /analyze_text - Comprehensive phishing analysis",
            "quick_check": "POST /quick_check - Quick phishing assessment",
            "analyze_links": "POST /analyze_links - Link-specific analysis"
        }
    }


@app.post("/analyze_text", response_model=AnalysisResponse)
async def analyze_text(request: TextAnalysisRequest):
    """
    Analyzes text content for comprehensive phishing indicators.
    
    Returns a detailed report with risk score and detected features.
    """
    try:
        features = extract_features(request.text)
        risk_score = calculate_risk_score(features)
        risk_level = get_risk_level(risk_score)
        
        report = ["📧 Phishing Analysis Report 📧\n"]
        report.append(f"Overall Risk Score: {risk_score:.2f}/1.00")
        report.append("\n--- Detected Features ---")
        
        for feature, present in features.items():
            emoji = "🚨" if present else "✅"
            feature_name = feature.replace('_', ' ').title()
            report.append(f"{emoji} {feature_name}: {'Yes' if present else 'No'}")
        
        report.append(f"\n--- Risk Level ---")
        report.append(f"⚠️ {risk_level}")
        
        return AnalysisResponse(
            result="\n".join(report),
            risk_score=risk_score,
            risk_level=risk_level
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/quick_check", response_model=AnalysisResponse)
async def quick_check(request: TextAnalysisRequest):
    """
    Provides a quick assessment of phishing likelihood.
    
    Returns a brief summary of the risk level.
    """
    try:
        features = extract_features(request.text)
        num_suspicious_features = sum(1 for present in features.values() if present)
        
        if num_suspicious_features >= 3:
            result = "🚨 High likelihood of phishing! Exercise extreme caution and do not interact."
        elif num_suspicious_features >= 1:
            result = "⚠️ Some suspicious elements detected. Review carefully before proceeding."
        else:
            result = "✅ Low risk - few or no suspicious elements detected."
            
        return AnalysisResponse(result=result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Quick check failed: {str(e)}")


@app.post("/analyze_links", response_model=AnalysisResponse)
async def analyze_links(request: TextAnalysisRequest):
    """
    Analyzes all links in the text for phishing risk.
    
    Returns a detailed report on each identified link.
    """
    try:
        # Find all URLs in the text
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', request.text)
        
        if not urls:
            return AnalysisResponse(result="No links found in the provided text.")
        
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
        
        return AnalysisResponse(result="\n".join(report))
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Link analysis failed: {str(e)}")


# --- Server Execution ---
if __name__ == "__main__":
    SERVER_PORT = 8000
    
    print(f"🚀 Starting Phishing Detection API server on http://localhost:{SERVER_PORT}...", file=sys.stderr)
    print("📡 Available endpoints:", file=sys.stderr)
    print("   POST /analyze_text - Comprehensive analysis", file=sys.stderr)
    print("   POST /quick_check - Quick assessment", file=sys.stderr)
    print("   POST /analyze_links - Link analysis", file=sys.stderr)
    print("💡 To stop the server, press Ctrl+C", file=sys.stderr)
    
    try:
        uvicorn.run(
            "phishing_detection:app",
            host="0.0.0.0",
            port=SERVER_PORT,
            reload=True
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user", file=sys.stderr)
    except Exception as e:
        print(f"💥 Server error: {e}", file=sys.stderr)
        sys.exit(1)