# Gmail Phishing Detector

A Chrome extension that scans Gmail emails for phishing attempts using both rule-based analysis and AI-powered detection with the Gemini API.

## Features

- 🛡️ **Rule-based Detection**: Analyzes emails for common phishing indicators like suspicious links, urgent language, and credential requests
- 🤖 **AI-powered Analysis**: Uses Google's Gemini AI to provide advanced phishing detection
- 📊 **Risk Assessment**: Calculates risk scores and provides clear risk levels (High, Medium, Low)
- 🔍 **Detailed Analysis**: Shows a comprehensive breakdown of suspicious elements
- 📱 **User-friendly Interface**: Clean UI with collapsible sections for different types of analysis

## Setup and Installation

### Prerequisites

- Python 3.8 or higher
- Google Chrome browser
- Gemini API key

### Backend Setup

1. Install required Python packages:
   ```
   pip install fastapi uvicorn google-generativeai python-dotenv
   ```

2. Set up your Gemini API key:
   - Create a `.env` file in the root directory
   - Add your API key: `GEMINI_API_KEY=your_api_key_here`

3. Start the server:
   ```
   python phishing_detection.py
   ```
   Or use the provided batch script:
   ```
   start_server.bat
   ```

### Chrome Extension Setup

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in the top right)
3. Click "Load unpacked" and select the project folder
4. The extension icon should appear in your toolbar

## Usage

1. Open Gmail in Chrome
2. Open an email you want to analyze
3. Click the extension icon in the toolbar
4. Click "Analyze Current Email"
5. View the analysis results in the popup

## Troubleshooting

### Common Issues

- **"AI analysis not available"**: Check if your Gemini API key is valid and properly set
- **"Could not communicate with Gmail tab"**: Make sure you have an email open in Gmail
- **"Analysis failed"**: Ensure the Python server is running at http://localhost:8000

### Diagnostic Tools

- **Test Server**: Run `python test_server.py` to check if the server is working properly
- **Debug Logs**: Check the server logs in the console or in the logs directory

## Components

- **phishing_detection.py**: Python backend with FastAPI for phishing detection
- **background.js**: Chrome extension background script for handling analysis requests
- **popup.html/js**: UI for displaying analysis results
- **content.js**: Content script for extracting email content from Gmail
- **manifest.json**: Chrome extension configuration


## Acknowledgments

- Google Gemini API for AI-powered analysis
- FastAPI for the Python web framework
