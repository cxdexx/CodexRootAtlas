#!/bin/bash

# Define the root labs directory
LABS_ROOT="labs"

echo "Starting CodexRootAtlas Labs Restructure..."

# --- 1. Create the new, structured lab directories (mkdir -p creates parents as needed) ---

# Phase 1: Foundations
mkdir -p "$LABS_ROOT/phase-1-foundations/networking"
mkdir -p "$LABS_ROOT/phase-1-foundations/linux-basics"
mkdir -p "$LABS_ROOT/phase-1-foundations/windows-basics"

# Phase 2: Core Skills (Web & API)
mkdir -p "$LABS_ROOT/phase-2-core-skills/web-app-local"
mkdir -p "$LABS_ROOT/phase-2-core-skills/web-writeups"

# Phase 3: Specialization
mkdir -p "$LABS_ROOT/phase-3-specialization/active-directory"
mkdir -p "$LABS_ROOT/phase-3-specialization/mobile"
mkdir -p "$LABS_ROOT/phase-3-specialization/containers"

# Phase 4: The Elite
mkdir -p "$LABS_ROOT/phase-4-elite/cloud"
mkdir -p "$LABS_ROOT/phase-4-elite/exploit-dev"

# Platform Writeups Consolidation
mkdir -p "$LABS_ROOT/platform-writeups/htb"
mkdir -p "$LABS_ROOT/platform-writeups/tryhackme"
mkdir -p "$LABS_ROOT/platform-writeups/overthewire"


# --- 2. Move existing content to the new locations ---

echo "Moving existing labs content..."

# Move local web apps (Juice Shop, DVWA, WebGoat) to phase-2/web-app-local
for lab in juice-shop dvwa webgoat; do
    if [ -d "$LABS_ROOT/$lab" ]; then
        mv "$LABS_ROOT/$lab" "$LABS_ROOT/phase-2-core-skills/web-app-local/"
        echo "Moved $lab"
    fi
done

# Move Hack The Box writeups to the new consolidated folder
if [ -d "$LABS_ROOT/htb" ]; then
    # Move the contents of the old htb folder into the new one
    mv "$LABS_ROOT/htb"/* "$LABS_ROOT/platform-writeups/htb/" 2>/dev/null
    # Remove the now-empty original directory
    rmdir "$LABS_ROOT/htb" 2>/dev/null
    echo "Moved HTB content"
fi

# Clean up any empty old directories if they exist after the move (optional but clean)
# This will only succeed if the directories were already empty or were emptied above
rmdir "$LABS_ROOT/juice-shop" "$LABS_ROOT/dvwa" "$LABS_ROOT/webgoat" 2>/dev/null


# --- 3. Final steps ---

echo "Restructure complete! Remember to update labs/README.md and commit these changes."
