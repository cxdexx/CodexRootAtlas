export default function SharedFragExplainer() {
  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🚨 SKBFL_SHARED_FRAG: The Critical Flag</h3>
        <p className="text-gray-200 mb-4">
          <span className="font-bold text-cyber-cyan">SKBFL_SHARED_FRAG</span> is a flag that tells the kernel: "This fragment points to memory that is shared with other parts of the system."
        </p>
        <p className="text-gray-200">
          When this flag is 1, the kernel knows it must copy the data before modifying it. If it's 0, the kernel assumes it can modify safely.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Flag = 1 (Safe) */}
        <div className="cyber-panel rounded-lg p-6 border-2 border-green-400 bg-green-400 bg-opacity-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="flag-badge active">SHARED_FRAG = 1</div>
            <span className="text-green-400 font-bold">✓ SAFE</span>
          </div>
          <div className="space-y-3">
            <p className="text-gray-200 font-bold">What it means:</p>
            <p className="text-gray-200 text-sm">
              This fragment points to a page that is shared (like a page cache page). Other processes might be reading from it.
            </p>
            <div className="bg-black bg-opacity-50 rounded p-3 mt-3">
              <p className="text-green-300 font-mono text-xs">
                Before modifying this data:<br/>
                1. Copy it to a new page<br/>
                2. Modify the copy<br/>
                3. Update fragment to point to copy
              </p>
            </div>
          </div>
        </div>

        {/* Flag = 0 (Danger) */}
        <div className="cyber-panel rounded-lg p-6 border-2 border-red-500 bg-red-500 bg-opacity-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="flag-badge inactive">SHARED_FRAG = 0</div>
            <span className="text-red-400 font-bold">⚠️ UNSAFE</span>
          </div>
          <div className="space-y-3">
            <p className="text-gray-200 font-bold">What it means:</p>
            <p className="text-gray-200 text-sm">
              This fragment points to private memory (or the kernel forgot it's shared). Safe to modify in place.
            </p>
            <div className="bg-black bg-opacity-50 rounded p-3 mt-3">
              <p className="text-red-300 font-mono text-xs">
                The kernel assumes:<br/>
                No one else is reading this<br/>
                Safe to modify in place<br/>
                (This assumption is WRONG!)
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">The splice() Attack Setup</h4>
        <p className="text-gray-200 text-sm mb-4">
          The Fragnesia attack starts with <span className="font-bold">splice()</span>, a Linux syscall that efficiently transfers data between file descriptors:
        </p>
        <div className="space-y-3">
          <div className="border-l-4 border-cyber-cyan pl-4 py-2">
            <p className="font-mono text-cyan-300 font-bold">Step 1: Read file into page cache</p>
            <p className="text-gray-300 text-sm">Open /usr/bin/su, triggering page cache loading</p>
          </div>
          <div className="border-l-4 border-cyber-pink pl-4 py-2">
            <p className="font-mono text-pink-300 font-bold">Step 2: splice() into socket</p>
            <p className="text-gray-300 text-sm">Use splice() to attach the page cache page as a fragment in an SKB</p>
          </div>
          <div className="border-l-4 border-cyan-400 pl-4 py-2">
            <p className="font-mono text-cyan-400 font-bold">Step 3: Flag is set automatically</p>
            <p className="text-gray-300 text-sm">Kernel sets SKBFL_SHARED_FRAG = 1 (page is shared with page cache)</p>
          </div>
        </div>
      </div>

      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// What splice() does internally</p>
        <pre className="text-cyan-400">{`// splice() attaches page cache page to SKB
ssize_t splice() {
  // Get page from page cache
  page = find_page_cache(file);
  
  // Create fragment pointing to it
  skb_frag_t *frag = &skb->frags[nr_frags];
  frag->page = page;
  frag->page_offset = offset;
  frag->size = len;
  
  // Kernel automatically sets this because
  // the page is shared with page cache
  shinfo->flags |= SKBFL_SHARED_FRAG;
  
  return bytes_spliced;
}
`}</pre>
      </div>

      <div className="cyber-panel rounded-lg p-6 border border-yellow-500 border-opacity-30 bg-yellow-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-yellow-400 mb-3">⚠️ Why This Matters</h4>
        <p className="text-gray-200 text-sm mb-3">
          At this point, the setup is safe. The flag is correctly set. The problem happens later when <span className="font-bold">skb_try_coalesce()</span> merges SKBs.
        </p>
        <p className="text-gray-200 text-sm">
          If the flag gets cleared during coalesce, the kernel forgets that this fragment is shared with the page cache—and treats it as private memory.
        </p>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>SKBFL_SHARED_FRAG = 1: "shared memory—copy before modifying"</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>SKBFL_SHARED_FRAG = 0: "private memory—safe to modify in place"</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>splice() correctly sets the flag when attaching page cache pages</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>The bug: the flag gets cleared incorrectly later</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
