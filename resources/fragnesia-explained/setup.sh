#!/bin/bash
# Quick setup script for Fragnesia Explained

echo "🚀 Fragnesia Explained - Quick Setup"
echo "===================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ from https://nodejs.org"
    exit 1
fi

echo "✓ Node.js version: $(node --version)"
echo "✓ npm version: $(npm --version)"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully!"
    echo ""
    echo "🎯 Next steps:"
    echo "   1. Start dev server:  npm run dev"
    echo "   2. Build for prod:    npm run build"
    echo "   3. Preview build:     npm run preview"
    echo ""
    echo "📖 Learn more in README.md"
else
    echo "❌ Installation failed. Please check your internet connection and try again."
    exit 1
fi
