#!/usr/bin/env python
# Simple test script to verify the phishing detection server is working

import requests
import json
import sys
import time

def test_api():
    """Test connection to both phishing detection API endpoints"""
    endpoints = [
        ("http://localhost:8000/quick_check", "Quick Check (Rule-based)"),
        ("http://localhost:8000/analyze_text", "Full Analysis (AI + Rules)")
    ]
    
    test_text = """
    Dear Customer,
    Your account has been compromised. Please click on this link to verify your account:
    http://amaz0n-security-alert.com/verify?id=123456
    You must update your information within 24 hours or your account will be suspended.
    
    Best regards,
    Security Team
    """
    
    all_success = True
    
    for url, name in endpoints:
        print(f"\n📤 Testing {name}...")
        try:
            response = requests.post(
                url,
                json={"text": test_text},
                headers={"Content-Type": "application/json"},
                timeout=15  # Longer timeout for AI endpoint
            )
            
            if response.status_code == 200:
                print(f"✅ {name} responded with status code {response.status_code}")
                try:
                    data = response.json()
                    print(f"   Risk level: {data.get('risk_level', 'unknown')}")
                    print(f"   Risk score: {data.get('risk_score', 'unknown')}")
                    print(f"   Features detected: {sum(1 for v in data.get('features', {}).values() if v)}")
                    
                    # Show first 100 chars of result
                    result = data.get('result', '')
                    if result:
                        print(f"   Result preview: {result[:100]}...")
                    
                except json.JSONDecodeError:
                    print(f"❌ Failed to parse {name} response as JSON")
                    print(f"   Raw response: {response.text[:200]}...")
                    all_success = False
            else:
                print(f"❌ {name} responded with status code {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                all_success = False
                
        except requests.exceptions.ConnectionError:
            print(f"❌ Could not connect to {name}. Make sure server is running.")
            all_success = False
        except requests.exceptions.Timeout:
            print(f"❌ {name} request timed out. Server might be overloaded.")
            all_success = False
        except Exception as e:
            print(f"❌ Error testing {name}: {str(e)}")
            all_success = False
    
    return all_success

def main():
    print("🔍 Testing phishing detection API server...")
    print("Attempting to connect to http://localhost:8000")
    
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        print(f"\nAttempt {attempt}/{max_attempts}:")
        if test_api():
            print("\n✅ Server test successful!")
            return True
        else:
            if attempt < max_attempts:
                print(f"⏱ Waiting 2 seconds before retry...")
                time.sleep(2)
    
    print("\n❌ All attempts failed. Please check if the server is running.")
    print("Run the server with: python phishing_detection.py")
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
