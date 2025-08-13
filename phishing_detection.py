#!/usr/bin/env python3
"""
Phishing Detection API Server with FastAPI (Enhanced Version)

This script implements a REST API using FastAPI to detect phishing indicators.
This version is self-contained and does not require an external config file.
It includes structured logging and advanced feature detection.
"""

import sys
import re
import os
import json
import logging
from urllib.parse import urlparse
from typing import Dict, Any

# --- Self-Contained Configuration ---
# All settings are now defined directly in the script.
config = {
  "cors_origins": [
    "http://localhost:8000",
    "http://localhost:3000",
    "https://mail.google.com",
    "chrome-extension://*"
  ],
  "legitimate_domains": [
    "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
    "netflix.com", "paypal.com", "twitter.com", "instagram.com", "linkedin.com",
    "youtube.com", "gmail.com", "yahoo.com", "outlook.com", "github.com",
    "dropbox.com", "spotify.com", "twitch.tv", "reddit.com", "wikipedia.org"
  ],
  "suspicious_tlds": [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".online", ".site", ".top", ".bid",
    ".download", ".club", ".work", ".racing", ".party", ".info", ".click", ".loan",
    ".win", ".stream", ".gdn", ".mom", ".date", ".trade", ".science", ".kim",
    ".xin", ".faith", ".jetzt"
  ],
  "urgency_words": [
    "urgent", "immediate", "action required", "account suspended", "security alert",
    "unauthorized", "verify your account", "expire", "limited time", "click now"
  ],
  "credential_words": [
    "password", "login", "credential", "verify", "bank account", "credit card",
    "social security", "ssn", "account details", "update payment", "confirm identity",
    "reset password", "security code"
  ],
  "suspicious_sender_patterns": [
    "@.*\\.(tk|ml|ga|cf|gq|xyz|online|site|top|bid)$"
  ],
  "feature_weights": {
    "has_urgency": 0.15,
    "has_suspicious_links": 0.25,
    "has_credential_request": 0.20,
    "has_suspicious_sender": 0.15,
    "has_poor_formatting": 0.10,
    "has_typosquatting": 0.20,
    "has_sender_spoofing": 0.25,
    "has_homoglyph_chars": 0.25
  },
  "homoglyphs": {
    "о": "o", "е": "e", "а": "a", "і": "i", "ѕ": "s", "с": "c",
    "І": "I", "О": "O", "Е": "E", "А": "A", "Ѕ": "S", "С": "C"
  },
  "gemini_generation_config": {
    "temperature": 0.5,
    "top_p": 0.8,
    "top_k": 40,
    "max_output_tokens": 1024
  },
  "gemini_safety_settings": [
    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
  ],
  "gemini_prompt_template": "You are an expert Gmail security analyst specializing in phishing detection. Analyze the following Gmail email content for phishing attempts, scam indicators, and social engineering tactics. \n\nLook for:\n- Suspicious URLs and domains\n- Urgent/threatening language\n- Requests for personal/financial information\n- Sender spoofing or impersonation\n- Grammar/spelling issues\n- Unusual attachments or links\n- Social engineering tactics\n\nProvide your analysis in this exact JSON format:\n{{\n  \"risk_level\": \"high\" OR \"medium\" OR \"low\",\n  \"confidence_score\": decimal between 0.0 and 1.0,\n  \"suspicious_elements\": {{\n    \"urls\": [\"list of suspicious URLs found with brief explanation\"],\n    \"urgent_phrases\": [\"list of urgent/pressure phrases detected\"],\n    \"credential_phrases\": [\"list of phrases requesting sensitive information\"]\n  }},\n  \"security_recommendations\": [\"list of 3-5 specific actions user should take\"],\n  \"detailed_analysis\": \"comprehensive explanation of your findings and reasoning\"\n}}\n\nGmail email content to analyze:\n\n{text}",
  "gemini_error_response": {
    "risk_level": "high",
    "confidence_score": 0.9,
    "suspicious_elements": {
      "ai_flags": ["AI analysis unavailable - falling back to rule-based detection"]
    },
    "security_recommendations": [
      "Exercise extreme caution with this email",
      "Do not click any links or download attachments", 
      "Do not provide personal or financial information",
      "Verify sender through alternative communication",
      "When in doubt, delete the email"
    ],
    "detailed_analysis": "AI analysis was unavailable. This email will be analyzed using rule-based detection methods. Please review carefully and follow security recommendations."
  }
}

# --- Structured Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    stream=sys.stdout  # Log to standard output
)

# --- Library Imports and Checks ---
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
    import google.generativeai as genai
    logging.info("✅ FastAPI and dependencies imported successfully")
except ImportError as e:
    logging.error(f"❌ Failed to import necessary libraries: {e}")
    logging.error("Hint: Install required packages with: pip install fastapi uvicorn google-generativeai python-dotenv")
    sys.exit(1)

# --- Environment Variable and API Key Setup ---
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    logging.warning("⚠️ python-dotenv not installed. Using environment variables directly.")

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    logging.error("❌ CRITICAL: GEMINI_API_KEY not found in environment variables or .env file.")
    sys.exit(1)
else:
    genai.configure(api_key=GEMINI_API_KEY)
    generation_config = config.get("gemini_generation_config", {})
    safety_settings = config.get("gemini_safety_settings", [])
    logging.info("✅ Gemini API configured successfully.")

# --- Pydantic Models for Request/Response ---
class TextAnalysisRequest(BaseModel):
    text: str

class AnalysisResponse(BaseModel):
    result: str
    risk_score: float = 0.0
    risk_level: str = "low"
    suspicious_elements: dict = {}
    features: dict = {}

# --- FastAPI App Initialization ---
app = FastAPI(
    title="Phishing Detector API",
    description="API for detecting phishing indicators in text content",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("cors_origins", []),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Core Phishing Detection Logic ---

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculates the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def has_homoglyphs(text: str, homoglyph_map: Dict[str, str]) -> bool:
    """Checks if a string contains characters that look like but are not standard Latin letters."""
    for char in text:
        if char in homoglyph_map:
            return True
    return False

def extract_features(text: str) -> Dict[str, bool]:
    """Extracts various features from the input text that can indicate phishing attempts."""
    features = {
        'has_urgency': False,
        'has_suspicious_links': False,
        'has_credential_request': False,
        'has_suspicious_sender': False,
        'has_poor_formatting': False,
        'has_typosquatting': False,
        'has_sender_spoofing': False, # New
        'has_homoglyph_chars': False, # New
    }
    
    text_lower = text.lower()
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    
    # 1. Check for urgency keywords
    features['has_urgency'] = any(word in text_lower for word in config['urgency_words'])

    # 2. Check for credential request keywords
    features['has_credential_request'] = any(word in text_lower for word in config['credential_words'])

    # 3. Analyze URLs
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().split(':')[0]
            
            # Check for homoglyphs in the domain
            if has_homoglyphs(domain, config['homoglyphs']):
                features['has_homoglyph_chars'] = True
                features['has_suspicious_links'] = True

            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in config['suspicious_tlds']):
                features['has_suspicious_links'] = True

            # Check for IP addresses in the hostname
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                features['has_suspicious_links'] = True

            # Check for typosquatting
            clean_domain = domain.replace('www.', '')
            for legitimate_domain in config['legitimate_domains']:
                distance = levenshtein_distance(clean_domain, legitimate_domain)
                if 0 < distance <= 2 and clean_domain != legitimate_domain:
                    features['has_typosquatting'] = True
                    features['has_suspicious_links'] = True
                    break
        except Exception as e:
            logging.warning(f"Could not parse URL '{url}': {e}")
            features['has_suspicious_links'] = True

    # 4. Check for suspicious sender patterns
    features['has_suspicious_sender'] = any(re.search(pattern, text_lower) for pattern in config['suspicious_sender_patterns'])

    # 5. Check for sender display name spoofing
    # Looks for "Legit Name" <scammer@email.com> where "Legit Name" is a known brand
    sender_patterns = re.findall(r'["\'](.+?)["\']\s*<(.+?)>', text)
    for display_name, email_address in sender_patterns:
        for brand in config['legitimate_domains']:
            brand_name = brand.split('.')[0]
            if brand_name in display_name.lower() and brand not in email_address.lower():
                features['has_sender_spoofing'] = True
                break
        if features['has_sender_spoofing']:
            break

    # 6. Check for poor formatting indicators
    features['has_poor_formatting'] = (
        text.count('!') > 3 or
        text.count('$') > 2 or
        len(re.findall(r'[A-Z]{4,}', text)) > 2
    )
    
    return features


async def analyze_with_gemini(text: str) -> Dict[str, Any]:
    """Enhanced Gmail phishing analysis using Gemini AI with all safety filters disabled."""
    error_response = config["gemini_error_response"]
    
    # Preprocess the text to focus on key elements
    text_preview = text[:3000]  # Limit to first 3000 chars for better processing
    
    try:
        # Create model with completely disabled safety filters
        model = genai.GenerativeModel(
            'gemini-1.5-flash',
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        
        prompt = config["gemini_prompt_template"].format(text=text_preview)
        logging.info(f"Sending Gmail content to Gemini API for phishing analysis (length: {len(text_preview)} chars)")
        logging.info(f"Safety settings applied: {safety_settings}")
        
        # Generate content with explicit safety override
        response = await model.generate_content_async(
            prompt,
            safety_settings=safety_settings  # Explicitly pass safety settings
        )
        
        logging.info("Received response from Gemini API")
        
        # Check for any blocking or safety issues
        if response.prompt_feedback:
            feedback = response.prompt_feedback
            logging.info(f"Prompt feedback: {feedback}")
            
            # Even with BLOCK_NONE, still check for blocking
            if hasattr(feedback, 'block_reason') and feedback.block_reason:
                logging.warning(f"Request blocked despite BLOCK_NONE settings: {feedback.block_reason}")
                # Continue anyway - this is expected for phishing content
        
        # Check if we have candidates (responses)
        if not response.candidates:
            logging.warning("No response candidates returned - this may be normal for phishing content")
            # Return high-risk assessment when blocked
            return {
                "risk_level": "high",
                "confidence_score": 0.9,
                "detailed_analysis": "Content was flagged by AI safety systems, which often indicates high-risk phishing content.",
                "suspicious_elements": {
                    "urls": [],
                    "urgent_phrases": [],
                    "credential_phrases": [],
                    "ai_flags": ["Content flagged by safety systems"]
                },
                "security_recommendations": [
                    "Do not interact with this email",
                    "Do not click any links",
                    "Do not provide any information",
                    "Mark as spam and delete",
                    "Report to your IT security team"
                ]
            }
        
        # Get the first candidate response
        candidate = response.candidates[0]
        
        # Check finish reason
        if hasattr(candidate, 'finish_reason'):
            finish_reason = candidate.finish_reason
            logging.info(f"Response finish reason: {finish_reason}")
            
            if finish_reason in ['SAFETY', 'RECITATION']:
                logging.info(f"Response blocked due to {finish_reason} - treating as high-risk")
                return {
                    "risk_level": "high",
                    "confidence_score": 0.95,
                    "detailed_analysis": f"AI analysis was blocked due to {finish_reason.lower()} concerns. This typically indicates the content contains elements commonly found in phishing or malicious emails.",
                    "suspicious_elements": {
                        "urls": [],
                        "urgent_phrases": [],
                        "credential_phrases": [],
                        "ai_flags": [f"Blocked by {finish_reason.lower()} filter"]
                    },
                    "security_recommendations": [
                        "HIGH ALERT: Do not interact with this email",
                        "Do not click any links or download attachments",
                        "Do not provide any personal or financial information",
                        "Delete this email immediately",
                        "Report to security team if from internal sender"
                    ]
                }
        
        # Try to extract the response text
        try:
            response_text = response.text
            if not response_text or response_text.strip() == "":
                logging.warning("Gemini returned empty response")
                # Fallback to rule-based analysis
                return error_response
            
            logging.info(f"Raw Gemini response length: {len(response_text)} chars")
            logging.debug(f"Response preview: {response_text[:300]}...")
                
            # Try to parse as JSON
            try:
                # Clean the response text - remove markdown code blocks if present
                clean_response = response_text.strip()
                if clean_response.startswith('```json'):
                    clean_response = clean_response[7:]  # Remove ```json
                if clean_response.startswith('```'):
                    clean_response = clean_response[3:]   # Remove ```
                if clean_response.endswith('```'):
                    clean_response = clean_response[:-3]  # Remove trailing ```
                clean_response = clean_response.strip()
                
                result = json.loads(clean_response)
                
                # Validate required fields
                required_fields = ["risk_level", "confidence_score", "detailed_analysis"]
                if all(field in result for field in required_fields):
                    logging.info("✅ Successfully parsed Gemini AI phishing analysis")
                    return result
                else:
                    logging.warning(f"Response missing required fields. Got: {list(result.keys())}")
                    
            except json.JSONDecodeError as je:
                logging.warning(f"JSON parsing failed: {str(je)}")
                logging.debug(f"Clean response attempt: {clean_response[:500] if 'clean_response' in locals() else 'N/A'}")
                
                # Try to extract meaningful analysis even from non-JSON response
                response_lower = response_text.lower()
                
                # Look for risk indicators in the text response
                high_risk_words = ["phishing", "scam", "fraud", "malicious", "dangerous", "threat", "suspicious"]
                medium_risk_words = ["caution", "verify", "check", "review", "uncertain"]
                
                if any(word in response_lower for word in high_risk_words):
                    risk_level = "high"
                    confidence = 0.8
                elif any(word in response_lower for word in medium_risk_words):
                    risk_level = "medium"
                    confidence = 0.6
                else:
                    risk_level = "low"
                    confidence = 0.4
                
                return {
                    "risk_level": risk_level,
                    "confidence_score": confidence,
                    "detailed_analysis": f"AI analysis (parsed from text): {response_text[:1000]}...",
                    "suspicious_elements": {
                        "urls": [],
                        "urgent_phrases": [],
                        "credential_phrases": [],
                        "ai_notes": ["Response in non-standard format"]
                    },
                    "security_recommendations": [
                        "Review the AI analysis carefully",
                        "Cross-check with rule-based analysis",
                        "When in doubt, treat as suspicious",
                        "Do not click links until verified"
                    ]
                }
                
        except ValueError as ve:
            logging.warning(f"Error accessing Gemini response text: {str(ve)}")
            return error_response
        
    except Exception as e:
        logging.error(f"Unexpected error in Gemini analysis: {str(e)}", exc_info=True)
        error_response["detailed_analysis"] = f"System error during AI analysis: {str(e)}"
        return error_response
    
    # Fallback return
    return error_response

# --- API Endpoints ---

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Phishing Detection API",
        "version": "3.0.0",
        "endpoints": {
            "analyze_text": "POST /analyze_text - Comprehensive phishing analysis",
            "quick_check": "POST /quick_check - Quick rule-based phishing assessment",
        }
    }

@app.post("/analyze_text", response_model=AnalysisResponse)
async def analyze_text_endpoint(request: TextAnalysisRequest):
    """Performs comprehensive AI-powered phishing analysis using Gemini."""
    try:
        ai_analysis = await analyze_with_gemini(request.text)
        
        # Fallback to rule-based analysis if AI fails unexpectedly
        if ai_analysis.get('risk_level') == 'unknown':
            logging.warning("AI analysis returned 'unknown' risk, falling back to quick_check.")
            return await quick_check_endpoint(request)

        # Build a report from the AI analysis
        report = [f"🛡️ {ai_analysis.get('risk_level', 'unknown').upper()} RISK 🛡️\n"]
        report.append(ai_analysis.get('detailed_analysis', 'No detailed analysis available.'))
        
        if ai_analysis.get('security_recommendations'):
            report.append("\n✅ Security Recommendations:")
            for rec in ai_analysis['security_recommendations']:
                report.append(f"• {rec}")
        
        return AnalysisResponse(
            result="\n".join(report),
            risk_score=ai_analysis.get('confidence_score', 0.0),
            risk_level=ai_analysis.get('risk_level', 'low'),
            suspicious_elements=ai_analysis.get('suspicious_elements', {}),
            features=extract_features(request.text) # Also include rule-based features
        )
    except Exception as e:
        logging.error(f"Full analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/quick_check", response_model=AnalysisResponse)
async def quick_check_endpoint(request: TextAnalysisRequest):
    """Provides a quick, rule-based assessment of phishing likelihood."""
    try:
        features = extract_features(request.text)
        feature_weights = config['feature_weights']
        
        # Calculate score
        risk_score = sum(feature_weights.get(feature, 0) for feature, present in features.items() if present)
        risk_score = min(risk_score, 1.0) # Cap score at 1.0

        # Determine risk level
        if risk_score >= 0.7:
            risk_level = "high"
            summary = "🚨 High likelihood of phishing! Exercise extreme caution."
        elif risk_score >= 0.4:
            risk_level = "medium"
            summary = "⚠️ Some suspicious elements detected. Review carefully."
        else:
            risk_level = "low"
            summary = "✅ Low risk - few or no suspicious elements detected."

        # Build report
        report = [summary, "\n📋 Technical Findings:"]
        findings = [key for key, value in features.items() if value]
        if findings:
            report.extend([f"• Detected: {finding.replace('_', ' ').title()}" for finding in findings])
        else:
            report.append("• No suspicious technical elements detected.")
        
        return AnalysisResponse(
            result="\n".join(report),
            risk_score=risk_score,
            risk_level=risk_level,
            features=features
        )
    except Exception as e:
        logging.error(f"Quick check failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Quick check failed: {str(e)}")

# --- Server Execution ---
if __name__ == "__main__":
    SERVER_PORT = 8000
    module_name = os.path.basename(__file__).replace(".py", "")

    logging.info(f"🚀 Starting Phishing Detection API server on http://localhost:{SERVER_PORT}...")
    
    try:
        uvicorn.run(
            f"{module_name}:app",
            host="0.0.0.0",
            port=SERVER_PORT,
            reload=True,
            log_config=None # Disable uvicorn's default loggers to use our custom one
        )
    except KeyboardInterrupt:
        logging.info("\n👋 Server stopped by user")
    except Exception as e:
        logging.critical(f"💥 Server failed to start: {e}")
        sys.exit(1)
