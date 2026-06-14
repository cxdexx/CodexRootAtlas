# Fragnesia Explained - Interactive Educational App

A comprehensive, interactive web application that explains the **Fragnesia Linux kernel vulnerability (CVE-2024-0604)** for beginner-to-intermediate cybersecurity learners.

## 🎯 What is Fragnesia?

Fragnesia is a critical Linux kernel vulnerability that allows privilege escalation through page cache corruption. The vulnerability exploits a bug in `skb_try_coalesce()` that loses the `SKBFL_SHARED_FRAG` flag, causing the kernel to incorrectly perform in-place AES-GCM decryption on shared page cache memory.

## 📚 Learning Sections

The app contains 11 interactive sections:

1. **What is the Page Cache?** - Understanding shared file caching in RAM
2. **What is a Socket Buffer?** - Network packet structures in the kernel
3. **What is a Fragment?** - Breaking down SKB data into scattered pages
4. **What is a Flag?** - Boolean markers controlling kernel behavior
5. **SKBFL_SHARED_FRAG Flag** - The critical flag that prevents corruption
6. **skb_try_coalesce() Function** - The function with the bug (interactive!)
7. **Safe vs Unsafe Paths** - How flags determine modification behavior (interactive!)
8. **AES-GCM In-Place Decryption** - Conceptual cryptography animation
9. **One-Byte Write Visualization** - How attackers corrupt binaries (interactive!)
10. **The Full Picture** - Complete attack timeline and summary
11. **Quiz** - 10 questions to test your understanding

## 🎨 Features

- ✅ **Dark Mode Cyber Design** - Sleek, modern interface inspired by cybersecurity aesthetics
- ✅ **Interactive Visualizations** - Click buttons to simulate kernel operations
- ✅ **Side-by-Side Navigation** - Left sidebar with section list, main content area
- ✅ **Progress Tracking** - Visual progress bar shows learning advancement
- ✅ **Comprehensive Quiz** - 10 questions with detailed explanations
- ✅ **Beginner-Friendly** - Explains kernel concepts without overwhelming jargon
- ✅ **No Exploit Code** - Educational only, no weaponized payloads or PoCs

## 🚀 Getting Started

### Prerequisites

- Node.js 16+ and npm
- Basic Linux/networking knowledge (recommended)

### Installation

```bash
cd fragnesia-explained
npm install
```

### Development Server

```bash
npm run dev
```

The app will open in your browser at `http://localhost:5174` (usually).

### Build for Production

```bash
npm run build
```

Output will be in the `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## 📁 Project Structure

```
fragnesia-explained/
├── src/
│   ├── components/
│   │   ├── PageCacheExplainer.tsx          # Page cache section
│   │   ├── SocketBufferExplainer.tsx       # Socket buffer section
│   │   ├── FragmentExplainer.tsx           # Fragment section
│   │   ├── FlagExplainer.tsx               # Flag section
│   │   ├── SharedFragExplainer.tsx         # SKBFL_SHARED_FRAG section
│   │   ├── CoalesceVisualizer.tsx          # Interactive coalesce simulator
│   │   ├── SafeVsUnsafePath.tsx            # Interactive safe/unsafe demo
│   │   ├── AESGCMAnimation.tsx             # Conceptual encryption demo
│   │   ├── ByteWriteVisual.tsx             # Interactive 1-byte write demo
│   │   ├── SummaryPanel.tsx                # Full attack summary
│   │   └── QuizSection.tsx                 # 10-question quiz
│   ├── App.tsx                              # Main app component
│   ├── main.tsx                             # React entry point
│   ├── index.css                            # Global styles + Tailwind
│   └── vite-env.d.ts                        # TypeScript definitions
├── index.html                               # HTML entry point
├── package.json                             # Dependencies
├── vite.config.ts                           # Vite configuration
├── tsconfig.json                            # TypeScript config
├── tailwind.config.js                       # Tailwind CSS theme
└── postcss.config.js                        # PostCSS config
```

## 🎓 Teaching Approach

Each section follows a consistent pattern:

1. **Conceptual Explanation** - Plain English description of the concept
2. **Visual Representation** - Diagrams and cards showing how it works
3. **Code Examples** - Simplified kernel code snippets
4. **Connection to Fragnesia** - How this concept relates to the vulnerability
5. **Interactive Demo** (where applicable) - Click to see it in action
6. **Key Takeaways** - Summary bullet points

## 🎬 Interactive Sections

### Safe vs Unsafe Paths (Section 7)
- Toggle the SKBFL_SHARED_FRAG flag on/off
- Click "Decrypt" to see what happens in each case
- Visualize how the flag controls the kernel's decision

### skb_try_coalesce() Visualizer (Section 6)
- Step through the coalesce process
- Watch the flag mysteriously disappear
- See how the merged SKB loses critical information

### One-Byte Write Demo (Section 9)
- Simulate multiple packet arrivals
- Each packet writes one byte to the page cache
- Build up a full corruption scenario

## 💻 Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type-safe JavaScript
- **Vite** - Lightning-fast build tool
- **Tailwind CSS** - Utility-first styling
- **PostCSS** - CSS processing

## 🎨 Design Highlights

- **Color Scheme**:
  - `#6d28d9` - Cyber Purple (primary)
  - `#ec4899` - Cyber Pink (accent)
  - `#06b6d4` - Cyber Cyan (highlights)
  - Dark backgrounds with gradient overlays

- **Typography**: Clean, readable fonts with cyber-style glow effects
- **Animations**: Smooth transitions and fade-ins
- **Responsiveness**: Works on desktop, tablet, and mobile

## 📖 Learning Outcomes

After completing this app, you will understand:

✓ How the Linux page cache works and why it's shared  
✓ What socket buffers are and how they carry network data  
✓ How fragments scatter data across different pages  
✓ What the SKBFL_SHARED_FRAG flag does  
✓ How skb_try_coalesce() caused the bug  
✓ Why in-place decryption is dangerous on shared memory  
✓ How one-byte writes can escalate privileges  
✓ The complete Fragnesia attack chain  
✓ Why security patches require careful review  

## ⚠️ Educational Disclaimer

This application is for **educational purposes only**. It explains the vulnerability conceptually without providing:

- Exploit code or proof-of-concept
- Weaponized payloads or commands
- Step-by-step attack instructions
- Working code that could be used maliciously

The goal is to help security professionals and students understand how kernel vulnerabilities work and why defensive programming matters.

## 🔗 References

- CVE-2024-0604 (Fragnesia)
- Linux Kernel source code
- Kernel Exploitation educational resources

## 📝 Component Details

### PageCacheExplainer.tsx
- Explains page cache concept
- Shows disk vs RAM representation
- Highlights the shared nature

### SocketBufferExplainer.tsx
- Describes SKB structure
- Explains typical flow through network stack
- Shows multi-SKB scenarios

### FragmentExplainer.tsx
- Visual representation of multi-fragment SKBs
- Efficiency explanation
- Connection to page cache risk

### FlagExplainer.tsx
- Binary representation of flags
- Common SKB flags overview
- Bit operation examples

### SharedFragExplainer.tsx
- Deep dive into SKBFL_SHARED_FRAG
- Flag = 1 vs Flag = 0 comparison
- splice() attack setup

### CoalesceVisualizer.tsx ⭐ Interactive
- Step-by-step visualization of coalesce
- Shows flag disappearing
- 4-step progression

### SafeVsUnsafePath.tsx ⭐ Interactive
- Toggle SKBFL_SHARED_FRAG flag
- Simulate modification paths
- See corruption in action

### AESGCMAnimation.tsx
- XOR-based encryption concept
- In-place vs copy decryption
- Why page cache corruption happens

### ByteWriteVisual.tsx ⭐ Interactive
- Show byte-by-byte corruption
- Progress tracking
- Exploitation scenario

### SummaryPanel.tsx
- Complete attack timeline (7 steps)
- Root cause analysis
- Why the attack works

### QuizSection.tsx
- 10 comprehensive questions
- Instant feedback with explanations
- Score tracking
- Performance-based messages

## 🎯 Usage Scenarios

**For Instructors:**
- Use as a teaching tool in cybersecurity courses
- Assign sections as homework
- Have students take the quiz

**For Self-Learners:**
- Work through sections sequentially
- Use interactive demos to explore concepts
- Take the quiz to assess understanding

**For Security Professionals:**
- Quick reference for understanding CVE-2024-0604
- Deep dive into kernel internals
- Reminder of why flags matter

## 🐛 Known Limitations

- No real kernel code execution (educational only)
- Simplified for clarity (actual kernel code is more complex)
- Interactive demos use random values (not real encryption)
- Quiz is read-only (no data persistence)

## 🚀 Future Enhancements

- Add code snippets from actual fixed kernel patches
- Implement more interactive kernel simulations
- Add video explanations for complex sections
- Create printable summary cards
- Add multi-language support

## 📄 License

Educational resource for learning purposes.

## ✍️ Notes

This application was built to make Linux kernel vulnerabilities understandable to beginners while maintaining technical accuracy. The focus is on conceptual understanding rather than exploitation.

---

**Start learning!** Open the app and begin with "What is the Page Cache?" to build your understanding from the ground up.
