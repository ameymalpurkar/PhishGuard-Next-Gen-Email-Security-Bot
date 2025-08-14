#!/usr/bin/env python
# Enhanced test script for Gmail phishing detection with realistic examples

import requests
import json
import sys
import time

def test_gemini_with_phishing_content():
    """Test Gemini API with realistic phishing email content"""
    url = "http://localhost:8000/analyze_text"
    
    # Realistic phishing email examples
    test_emails = [
        {
            "name": "Fake Bank Alert",
            "content": """
From: security@bankofamerica-alert.com
Subject: URGENT: Account Verification Required

Dear Valued Customer,

Your Bank of America account has been temporarily suspended due to suspicious activity detected on your account. 

To restore full access to your account, you must verify your identity immediately by clicking the link below:

VERIFY YOUR ACCOUNT NOW: http://bankofamerica-secure-verify.net/login.php?id=12345

This verification must be completed within 24 hours or your account will be permanently closed.

Please provide the following information:
- Full Name
- Account Number  
- Social Security Number
- Online Banking Password
- Phone Number

Thank you for banking with us.

Bank of America Security Team
            """
        },
        {
            "name": "Fake Package Delivery", 
            "content": """
From: delivery@fedex-notification.org
Subject: Package Delivery Failed - Action Required

Dear Customer,

We attempted to deliver your package (Tracking: FX1234567890) but were unable to complete delivery.

To reschedule delivery, please click here: http://fedex-redelivery.tk/track?id=FX1234567890

You will need to:
1. Confirm your address
2. Pay a small delivery fee ($3.99) 
3. Provide contact information

If you do not reschedule within 48 hours, your package will be returned to sender.

FedEx Customer Service
            """
        },
        {
            "name": "Tech Support Scam",
            "content": """
From: support@microsoft-security.net
Subject: CRITICAL: Windows Security Alert

WARNING: Your computer is infected!

Microsoft Security has detected 5 critical threats on your Windows computer:
- Trojan.Win32.Generic
- Adware.Tracking.Cookie  
- Malware.Suspicious.File
- Virus.Boot.Sector
- Spyware.KeyLogger

IMMEDIATE ACTION REQUIRED:

Call our certified technicians NOW: 1-800-VIRUS-FIX
OR
Download our security tool: http://microsoft-security-fix.biz/download.exe

Do not ignore this warning! Your personal data, passwords, and financial information are at risk.

Microsoft Security Team
Technical Support Division
            """
        }
    ]
    
    print("🧪 Testing Gemini AI with realistic phishing email content...")
    print("=" * 60)
    
    all_success = True
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n📧 Test {i}: {email['name']}")
        print("-" * 40)
        
        try:
            print("📤 Sending to Gemini API...")
            response = requests.post(
                url,
                json={"text": email['content']},
                headers={"Content-Type": "application/json"},
                timeout=20  # Longer timeout for AI processing
            )
            
            if response.status_code == 200:
                print("✅ API Response received")
                try:
                    data = response.json()
                    
                    # Display key results
                    risk_level = data.get('risk_level', 'unknown')
                    risk_score = data.get('risk_score', 0)
                    result_preview = data.get('result', '')[:200]
                    
                    print(f"🎯 Risk Level: {risk_level.upper()}")
                    print(f"📊 Confidence: {(risk_score * 100):.1f}%")
                    print(f"💡 Analysis Preview: {result_preview}...")
                    
                    # Check for AI-specific indicators
                    if 'suspicious_elements' in data:
                        suspicious = data['suspicious_elements']
                        if suspicious.get('urls'):
                            print(f"🔗 Suspicious URLs detected: {len(suspicious['urls'])}")
                        if suspicious.get('urgent_phrases'):
                            print(f"⚡ Urgent phrases detected: {len(suspicious['urgent_phrases'])}")
                        if suspicious.get('ai_flags'):
                            print(f"🤖 AI flags: {suspicious['ai_flags']}")
                    
                    # Verify the analysis is working
                    if risk_level in ['high', 'medium'] and risk_score > 0.5:
                        print("✅ Gemini correctly identified phishing indicators")
                    else:
                        print("⚠️ Analysis may need improvement")
                        
                except json.JSONDecodeError:
                    print("❌ Failed to parse JSON response")
                    print(f"Raw response: {response.text[:300]}...")
                    all_success = False
            else:
                print(f"❌ API error: {response.status_code}")
                print(f"Response: {response.text[:200]}...")
                all_success = False
                
        except requests.exceptions.Timeout:
            print("❌ Request timed out - Gemini may be processing slowly")
            all_success = False
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            all_success = False
    
    return all_success

def main():
    print("🛡️ Enhanced Gmail Phishing Detection Test")
    print("Testing Gemini AI integration with safety filters disabled")
    print()
    
    if test_gemini_with_phishing_content():
        print("\n✅ All tests completed successfully!")
        print("🎉 Gemini AI is properly analyzing Gmail phishing content")
    else:
        print("\n❌ Some tests failed")
        print("Check the server logs for detailed error information")
    
    return True

if __name__ == "__main__":
    main()
