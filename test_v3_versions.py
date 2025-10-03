#!/usr/bin/env python3
"""
Test script to verify version consistency in the v3 branch
"""

import json
import sys
import re

def test_manifest_version():
    """Test that manifest.json has version 3.0"""
    with open('manifest.json', 'r') as f:
        manifest = json.load(f)
    
    version = manifest.get('version')
    if version == '3.0':
        print(f"✅ manifest.json version is correct: {version}")
        return True
    else:
        print(f"❌ manifest.json version is incorrect: {version} (expected 3.0)")
        return False

def test_phishing_detection_version():
    """Test that phishing_detection.py has version 3.0.0"""
    with open('phishing_detection.py', 'r') as f:
        content = f.read()
    
    # Find version in FastAPI app initialization
    version_match = re.search(r'version="(\d+\.\d+\.\d+)"', content)
    if version_match:
        version = version_match.group(1)
        if version == '3.0.0':
            print(f"✅ phishing_detection.py API version is correct: {version}")
            return True
        else:
            print(f"❌ phishing_detection.py API version is incorrect: {version} (expected 3.0.0)")
            return False
    else:
        print("❌ Could not find version in phishing_detection.py")
        return False

def test_api_endpoint_version():
    """Test that the root endpoint returns version 3.0.0"""
    with open('phishing_detection.py', 'r') as f:
        content = f.read()
    
    # Find version in root endpoint
    version_match = re.search(r'"version":\s*"(\d+\.\d+\.\d+)"', content)
    if version_match:
        version = version_match.group(1)
        if version == '3.0.0':
            print(f"✅ API endpoint version is correct: {version}")
            return True
        else:
            print(f"❌ API endpoint version is incorrect: {version} (expected 3.0.0)")
            return False
    else:
        print("❌ Could not find version in API endpoint")
        return False

def main():
    print("🧪 Testing v3 branch version consistency...\n")
    
    results = [
        test_manifest_version(),
        test_phishing_detection_version(),
        test_api_endpoint_version()
    ]
    
    if all(results):
        print("\n✅ All version tests passed!")
        return 0
    else:
        print("\n❌ Some version tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
