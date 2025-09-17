#!/bin/bash

# After creating the repository on GitHub, run this script to push the code

echo "Pushing to GitHub..."

# Add remote origin (replace USERNAME with your GitHub username)
git remote add origin https://github.com/USERNAME/checkmarx-npm-scanner.git

# Push to main branch
git push -u origin main

echo "✅ Code pushed to GitHub successfully!"
echo "Repository URL: https://github.com/USERNAME/checkmarx-npm-scanner"