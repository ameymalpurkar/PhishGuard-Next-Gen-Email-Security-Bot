#!/usr/bin/env python
# Simple test to see the exact API response format

import requests
import json

def test_api_response():
    """Test what the API actually returns"""
    url = "http://localhost:8000/analyze_text"
    test_text = """
    URGENT: Your account will be suspended!
    
    Dear Customer,
    Your account has been compromised. Click here to verify: http://fake-bank.com/verify
    Enter your password immediately or lose access forever!
    """
    
    print("🔍 Testing API response format...")
    try:
        response = requests.post(
            url,
            json={"text": test_text},
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Raw API Response:")
            print("=" * 50)
            print(json.dumps(data, indent=2))
            print("=" * 50)
            
            print("\n🔍 Key Analysis:")
            print(f"Risk Level: {data.get('risk_level', 'N/A')}")
            print(f"Risk Score: {data.get('risk_score', 'N/A')}")
            print(f"Has 'detailed_analysis'?: {'detailed_analysis' in data}")
            print(f"Has 'suspicious_elements'?: {'suspicious_elements' in data}")
            print(f"Has 'security_recommendations'?: {'security_recommendations' in data}")
            
            if 'detailed_analysis' in data:
                print(f"\n📝 Detailed Analysis Preview:")
                print(f"{data['detailed_analysis'][:200]}...")
                
        else:
            print(f"❌ API Error: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_api_response()
