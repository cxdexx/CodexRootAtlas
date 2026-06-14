export default function SocketBufferExplainer() {
  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">📦 What is a Socket Buffer (SKB)?</h3>
        <p className="text-gray-200 mb-4">
          When data travels over the network (TCP, UDP, etc.), the kernel stores it in structures called <span className="font-bold text-cyber-cyan">socket buffers (SKB)</span>.
        </p>
        <p className="text-gray-200 mb-4">
          An SKB holds incoming packets and tracks metadata about them. Think of it as a container with a packet inside plus a label that describes what's in the container.
        </p>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">Anatomy of a Socket Buffer</h4>
        <div className="space-y-3">
          <div className="border-l-4 border-cyber-cyan pl-4 py-2">
            <p className="font-mono text-cyber-cyan font-bold">data pointer</p>
            <p className="text-gray-300 text-sm">Points to the actual packet data in memory</p>
          </div>
          <div className="border-l-4 border-cyber-pink pl-4 py-2">
            <p className="font-mono text-cyber-pink font-bold">len</p>
            <p className="text-gray-300 text-sm">How many bytes of data this SKB contains</p>
          </div>
          <div className="border-l-4 border-cyber-cyan pl-4 py-2">
            <p className="font-mono text-cyber-cyan font-bold">flags</p>
            <p className="text-gray-300 text-sm">Boolean markers (like SKBFL_SHARED_FRAG) for behavior</p>
          </div>
          <div className="border-l-4 border-cyber-pink pl-4 py-2">
            <p className="font-mono text-cyber-pink font-bold">frags</p>
            <p className="text-gray-300 text-sm">Array of fragments (pages) that make up the data</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="cyber-panel rounded-lg p-6 border border-green-500 border-opacity-30 bg-green-500 bg-opacity-5">
          <h4 className="text-lg font-bold text-green-400 mb-3">Typical Flow</h4>
          <ol className="text-gray-200 text-sm space-y-2">
            <li><span className="text-green-400 font-bold">1.</span> Network card receives packet</li>
            <li><span className="text-green-400 font-bold">2.</span> Kernel creates SKB with packet data</li>
            <li><span className="text-green-400 font-bold">3.</span> SKB travels through network stack</li>
            <li><span className="text-green-400 font-bold">4.</span> Application reads from SKB</li>
          </ol>
        </div>

        <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
          <h4 className="text-lg font-bold text-cyber-cyan mb-3">Multiple SKBs</h4>
          <p className="text-gray-200 text-sm mb-3">
            Often several packets arrive together. Each gets its own SKB, or they get merged into one SKB with multiple fragments.
          </p>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-12 h-12 rounded border-2 border-cyber-cyan flex items-center justify-center text-xs font-mono">SKB1</div>
              <div className="text-cyber-cyan">→</div>
              <div className="w-12 h-12 rounded border-2 border-cyber-pink flex items-center justify-center text-xs font-mono">SKB2</div>
            </div>
          </div>
        </div>
      </div>

      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// Simplified SKB structure</p>
        <pre className="text-cyan-400">{`struct sk_buff {
  unsigned char *data;        // Points to packet data
  unsigned int len;           // Data length
  
  skb_shared_info *shinfo;    // Shared info & frags
  struct {
    unsigned int flags;       // SKBFL_SHARED_FRAG, etc.
    skb_frag_t frags[16];     // Fragment array
    unsigned int nr_frags;    // Number of frags
  } *shinfo;
}

struct skb_frag_t {
  struct page *page;          // Points to a page in RAM
  unsigned int page_offset;   // Offset within page
  unsigned int size;          // Fragment size
}
`}</pre>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-yellow-500 border-opacity-30 bg-yellow-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-yellow-400 mb-3">⚠️ Why This Matters for Fragnesia</h4>
        <p className="text-gray-200 text-sm">
          An SKB fragment can point to a page in the page cache. If that flag gets lost, the kernel might think it's safe to modify that page—even though other processes are using it through the page cache.
        </p>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Socket buffers carry network packets through the kernel</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>An SKB has data, metadata, flags, and fragments</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Fragments are pieces of data (often pages from page cache)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Flags describe how to safely handle the data</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
