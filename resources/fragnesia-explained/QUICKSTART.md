# 🚀 QUICKSTART

Get Fragnesia Explained running in 2 minutes.

## Prerequisites

- Node.js 16+ and npm installed
- ~300MB disk space for node_modules

## Installation & Run

### Option 1: Using npm directly

```bash
# Install dependencies
npm install

# Start dev server
npm run dev
```

The app opens automatically at `http://localhost:5174`

### Option 2: Using the setup script

```bash
chmod +x setup.sh
./setup.sh
npm run dev
```

## Available Commands

```bash
# Development server (with hot reload)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Troubleshooting

**Port 5174 already in use?**
```bash
# Vite will automatically use the next available port
npm run dev
```

**Module not found errors?**
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

**TypeScript errors?**
```bash
# Make sure you're in the right directory
cd fragnesia-explained
npm install
```

## 📖 Learning Path

1. Start with **Section 1: What is the Page Cache?**
2. Work through sections sequentially
3. Use interactive demos to explore concepts
4. Take the **Quiz** at the end to test understanding

## 🎓 Learning Topics

- Page caching in Linux
- Socket buffers and fragments
- Kernel flags and their importance
- AES-GCM encryption
- The complete Fragnesia attack chain
- Why security patches matter

## 💡 Tips

- Read each explanation carefully before clicking interactive buttons
- The "Mental Model" boxes explain concepts in simple terms
- Check the quiz explanations even for correct answers
- Review sections if quiz questions seem hard

---

**That's it!** You're ready to learn about Fragnesia. Happy learning! 🎓
