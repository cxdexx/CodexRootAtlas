export default function FlagExplainer() {
  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🚩 What is a Flag?</h3>
        <p className="text-gray-200 mb-4">
          A <span className="font-bold text-cyber-cyan">flag</span> in kernel code is a boolean marker (1 or 0) that tells the kernel how to behave. Flags are collected into a single integer where each bit represents one flag.
        </p>
        <p className="text-gray-200">
          Think of a flag as a warning sticker: "⚠️ HANDLE WITH CARE" or "✅ SAFE TO MODIFY".
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Bit Representation */}
        <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
          <h4 className="text-lg font-bold text-cyber-purple mb-4">Binary Representation</h4>
          <p className="text-gray-200 text-sm mb-4">
            Flags are stored as bits in a single 32 or 64-bit integer:
          </p>
          <div className="font-mono text-xs space-y-2">
            <div className="bg-black bg-opacity-50 p-3 rounded text-cyan-300">
              <p className="mb-2">flags = 0b10110101</p>
              <p className="text-gray-400">Bit 0: 1 (flag active)</p>
              <p className="text-gray-400">Bit 1: 0 (flag inactive)</p>
              <p className="text-gray-400">Bit 2: 1 (flag active)</p>
              <p className="text-gray-400">...</p>
            </div>
          </div>
        </div>

        {/* Check/Set Operations */}
        <div className="cyber-panel rounded-lg p-6 border border-cyber-pink border-opacity-30">
          <h4 className="text-lg font-bold text-cyber-pink mb-4">Flag Operations</h4>
          <div className="space-y-3 font-mono text-xs">
            <div className="bg-black bg-opacity-50 p-3 rounded text-pink-300">
              <p className="font-bold mb-2">Check if flag is set:</p>
              <p className="text-gray-300">if (flags & FLAG_BIT)</p>
            </div>
            <div className="bg-black bg-opacity-50 p-3 rounded text-pink-300">
              <p className="font-bold mb-2">Set a flag:</p>
              <p className="text-gray-300">flags |= FLAG_BIT</p>
            </div>
            <div className="bg-black bg-opacity-50 p-3 rounded text-pink-300">
              <p className="font-bold mb-2">Clear a flag:</p>
              <p className="text-gray-300">flags &= ~FLAG_BIT</p>
            </div>
          </div>
        </div>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-cyan-400 border-opacity-30">
        <h4 className="text-lg font-bold text-cyan-400 mb-4">Common SKB Flags</h4>
        <div className="space-y-3">
          <div className="border-l-4 border-cyber-cyan pl-4 py-2">
            <p className="font-mono text-cyber-cyan font-bold">SKBFL_SHARED_FRAG</p>
            <p className="text-gray-300 text-sm">Fragment points to shared memory (page cache). Copy before modifying.</p>
          </div>
          <div className="border-l-4 border-cyber-pink pl-4 py-2">
            <p className="font-mono text-cyber-pink font-bold">SKBFL_CLONED</p>
            <p className="text-gray-300 text-sm">This SKB is a clone of another. Don't modify.</p>
          </div>
          <div className="border-l-4 border-cyber-cyan pl-4 py-2">
            <p className="font-mono text-cyber-cyan font-bold">SKBFL_SHARED</p>
            <p className="text-gray-300 text-sm">This SKB is shared with other SKBs. Don't modify.</p>
          </div>
          <div className="border-l-4 border-cyan-400 pl-4 py-2">
            <p className="font-mono text-cyan-400 font-bold">SKBFL_PURE_GSO</p>
            <p className="text-gray-300 text-sm">All fragments are pure pages (no headers).</p>
          </div>
        </div>
      </div>

      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// Simplified kernel code</p>
        <pre className="text-cyan-400">{`#define SKBFL_SHARED_FRAG    (1U << 0)  // Bit 0
#define SKBFL_CLONED         (1U << 1)  // Bit 1
#define SKBFL_SHARED         (1U << 2)  // Bit 2

struct sk_buff {
  // ...
  unsigned int flags;
};

// Check if shared frag flag is set
if (skb->flags & SKBFL_SHARED_FRAG) {
  // This fragment shares memory with page cache
  // SAFE PATH: Copy the data before modifying
  skb_copy_ubufs(skb);
}

// Clear the flag
skb->flags &= ~SKBFL_SHARED_FRAG;
`}</pre>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-red-500 border-opacity-30 bg-red-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-red-400 mb-3">🔴 The Fragnesia Bug</h4>
        <p className="text-gray-200 text-sm">
          The bug happens when <span className="font-bold">SKBFL_SHARED_FRAG gets cleared</span> even though the fragment still points to shared page cache memory. The kernel then thinks it's safe to modify in place, but it's actually corrupting the page cache.
        </p>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-green-500 border-opacity-30 bg-green-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-green-400 mb-3">💡 Mental Model</h4>
        <p className="text-gray-200 text-sm">
          A flag is like a sticker on a package. <span className="font-bold">SKBFL_SHARED_FRAG = 1</span> means "⚠️ This is shared memory—make a copy before editing". <span className="font-bold">SKBFL_SHARED_FRAG = 0</span> means "✅ Safe to edit directly".
        </p>
        <p className="text-gray-200 text-sm mt-3">
          If you remove the sticker while the package is still shared, someone will ignore the warning and modify something they shouldn't touch.
        </p>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Flags are bits in an integer that control kernel behavior</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>SKBFL_SHARED_FRAG = 1 means "don't modify in place"</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>SKBFL_SHARED_FRAG = 0 means "safe to modify"</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Fragnesia exploits the loss of this flag</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
