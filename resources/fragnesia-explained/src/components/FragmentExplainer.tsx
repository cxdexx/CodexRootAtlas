export default function FragmentExplainer() {
  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🔗 What is a Fragment?</h3>
        <p className="text-gray-200 mb-4">
          A <span className="font-bold text-cyber-cyan">fragment</span> is a piece of data within a socket buffer. Instead of storing all packet data in one contiguous block, the kernel often uses multiple fragments that can be scattered across different pages in RAM.
        </p>
        <p className="text-gray-200">
          This is more efficient than copying data around. Each fragment is just a pointer to a page plus an offset and size.
        </p>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">Visual: A Multi-Fragment SKB</h4>
        <div className="space-y-4">
          <div>
            <p className="text-gray-400 text-sm mb-3">An SKB containing 3 fragments:</p>
          </div>
          
          {/* Fragment 1 */}
          <div className="border border-cyber-cyan border-opacity-50 rounded p-4 bg-cyber-dark bg-opacity-50">
            <div className="flex items-center gap-4">
              <div className="w-16 h-12 border-2 border-cyber-cyan rounded flex items-center justify-center font-mono text-xs bg-cyber-cyan bg-opacity-10">
                Frag 1
              </div>
              <div className="flex-1">
                <p className="font-mono text-cyan-300 text-sm">page_addr: 0x1000</p>
                <p className="font-mono text-cyan-300 text-sm">offset: 0, size: 256</p>
                <p className="text-gray-400 text-xs">→ Bytes [0:256]</p>
              </div>
            </div>
          </div>

          {/* Fragment 2 */}
          <div className="border border-cyber-pink border-opacity-50 rounded p-4 bg-cyber-dark bg-opacity-50">
            <div className="flex items-center gap-4">
              <div className="w-16 h-12 border-2 border-cyber-pink rounded flex items-center justify-center font-mono text-xs bg-cyber-pink bg-opacity-10">
                Frag 2
              </div>
              <div className="flex-1">
                <p className="font-mono text-pink-300 text-sm">page_addr: 0x2000</p>
                <p className="font-mono text-pink-300 text-sm">offset: 128, size: 256</p>
                <p className="text-gray-400 text-xs">→ Bytes [256:512]</p>
              </div>
            </div>
          </div>

          {/* Fragment 3 */}
          <div className="border border-cyan-400 border-opacity-50 rounded p-4 bg-cyber-dark bg-opacity-50">
            <div className="flex items-center gap-4">
              <div className="w-16 h-12 border-2 border-cyan-400 rounded flex items-center justify-center font-mono text-xs bg-cyan-400 bg-opacity-10">
                Frag 3
              </div>
              <div className="flex-1">
                <p className="font-mono text-cyan-400 text-sm">page_addr: 0x3000</p>
                <p className="font-mono text-cyan-400 text-sm">offset: 0, size: 100</p>
                <p className="text-gray-400 text-xs">→ Bytes [512:612]</p>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-4 text-gray-400 text-sm p-3 bg-black bg-opacity-40 rounded">
          <p>This SKB holds 612 bytes total, spread across 3 different pages in memory</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="cyber-panel rounded-lg p-6 border border-green-500 border-opacity-30 bg-green-500 bg-opacity-5">
          <h4 className="text-lg font-bold text-green-400 mb-3">✅ Why Fragments are Efficient</h4>
          <ul className="text-gray-200 text-sm space-y-2">
            <li className="flex items-start gap-2">
              <span className="text-green-400 font-bold">•</span>
              <span>No need to copy data between pages</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-400 font-bold">•</span>
              <span>Fragments just point to existing pages</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-400 font-bold">•</span>
              <span>Reduces memory overhead</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-400 font-bold">•</span>
              <span>Faster network processing</span>
            </li>
          </ul>
        </div>

        <div className="cyber-panel rounded-lg p-6 border border-yellow-500 border-opacity-30 bg-yellow-500 bg-opacity-5">
          <h4 className="text-lg font-bold text-yellow-400 mb-3">⚠️ The Risk with Page Cache</h4>
          <p className="text-gray-200 text-sm mb-3">
            If a fragment points to a page in the page cache, and you modify that fragment, you're modifying the page cache directly.
          </p>
          <p className="text-gray-200 text-sm">
            Other processes reading that file will see your modification!
          </p>
        </div>
      </div>

      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// How to iterate through fragments</p>
        <pre className="text-cyan-400">{`struct skb_shared_info *shinfo = skb_shinfo(skb);

for (i = 0; i < shinfo->nr_frags; i++) {
  struct skb_frag_t *frag = &shinfo->frags[i];
  
  // Get the page and offset
  struct page *page = frag->bv_page;
  unsigned int offset = frag->bv_offset;
  unsigned int size = frag->bv_len;
  
  // Access data
  void *vaddr = page_address(page) + offset;
  
  // Process size bytes at vaddr
}
`}</pre>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-cyber-pink border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-pink mb-3">🎯 Key Insight for Fragnesia</h4>
        <p className="text-gray-200">
          Fragnesia exploits the fact that fragments can point to page cache pages. The attack uses <span className="font-bold">splice()</span> to attach a page cache page as a fragment in an SKB, then triggers a coalesce operation that loses the shared fragment flag—making the kernel think it's safe to modify the page in place.
        </p>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Fragments are pieces of an SKB spread across different pages</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Each fragment points to a page, offset, and size</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Fragments can point to page cache pages</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>This creates the attack surface for Fragnesia</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
