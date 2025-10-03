#!/bin/bash
# Helper script to push the v3 branch to remote repository
# This script should be run by someone with push credentials

echo "🚀 V3 Branch Push Helper Script"
echo "================================"
echo ""

# Check if v3 branch exists locally
if git show-ref --verify --quiet refs/heads/v3; then
    echo "✅ v3 branch exists locally"
    
    # Show the last commit on v3
    echo ""
    echo "Last commit on v3 branch:"
    git log v3 -1 --oneline
    echo ""
    
    # Check if v3 already exists on remote
    if git ls-remote --heads origin v3 | grep -q v3; then
        echo "⚠️  v3 branch already exists on remote"
        echo "Do you want to force push? (y/n)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "Force pushing v3 branch..."
            git push -f origin v3
        else
            echo "Aborting push operation"
            exit 1
        fi
    else
        echo "📤 Pushing v3 branch to remote..."
        git push -u origin v3
    fi
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ Successfully pushed v3 branch to remote!"
        echo ""
        echo "You can now view it at:"
        echo "https://github.com/ameymalpurkar/PhishGuard-Next-Gen-Email-Security-Bot/tree/v3"
    else
        echo ""
        echo "❌ Failed to push v3 branch"
        exit 1
    fi
else
    echo "❌ v3 branch does not exist locally"
    echo "Please create it first with: git checkout -b v3"
    exit 1
fi
