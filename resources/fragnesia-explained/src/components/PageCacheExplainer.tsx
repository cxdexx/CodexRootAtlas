export default function PageCacheExplainer() {
  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🗂️ What is the Page Cache?</h3>
        <p className="text-gray-200 mb-4">
          When you open a file on disk, Linux doesn't just keep the disk copy. Instead, it creates a copy in RAM called the <span className="font-bold text-cyber-cyan">page cache</span>.
        </p>
        <p className="text-gray-200 mb-4">
          This cache makes reading files faster because RAM is much faster than disk. Multiple processes can read from the same cached page.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Disk Representation */}
        <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
          <h4 className="text-lg font-bold text-cyber-purple mb-4">💾 Disk</h4>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex-1 bg-gray-700 rounded p-3 font-mono text-sm">
                /usr/bin/su
              </div>
              <div className="text-2xl">→</div>
            </div>
            <p className="text-gray-400 text-sm">Original file on disk (not modified)</p>
          </div>
        </div>

        {/* Page Cache Representation */}
        <div className="cyber-panel rounded-lg p-6 border border-cyber-pink border-opacity-30">
          <h4 className="text-lg font-bold text-cyber-pink mb-4">⚡ RAM (Page Cache)</h4>
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex-1 bg-gradient-to-r from-cyber-pink to-purple-600 rounded p-3 font-mono text-sm font-bold">
                [su binary copy]
              </div>
            </div>
            <p className="text-gray-400 text-sm">Fast copy in RAM (can be modified)</p>
          </div>
        </div>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-yellow-500 border-opacity-30 bg-yellow-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-yellow-400 mb-3">⚠️ The Key Problem</h4>
        <p className="text-gray-200">
          If malicious code can modify the page cache copy of <span className="font-bold">/usr/bin/su</span>, every process that reads from that cache will get the modified version. This is why page cache corruption is dangerous.
        </p>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-green-500 border-opacity-30 bg-green-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-green-400 mb-3">💡 Mental Model</h4>
        <p className="text-gray-200">
          The page cache is a shared memo board. If someone secretly erases part of it, everyone who reads that memo gets the wrong information.
        </p>
      </div>

      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// Linux kernel pseudo-code concept</p>
        <pre className="text-cyan-400">{`struct page {
  void *addr;        // Points to cached data in RAM
  int ref_count;     // How many use this page
  // ... other fields
}

// When a file is read:
page = find_page_cache(filename);
if (page) {
  return page.addr;  // Fast! From RAM
}
`}</pre>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Page cache stores file copies in RAM for speed</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Multiple processes can share the same cached page</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Modifying the cache affects all readers</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Fragnesia exploits this shared nature</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
