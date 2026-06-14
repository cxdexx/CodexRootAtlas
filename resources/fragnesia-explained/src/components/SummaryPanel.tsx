export default function SummaryPanel() {
  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🎯 The Full Picture</h3>
        <p className="text-gray-200">
          Let's bring everything together. Here's what happened in Fragnesia:
        </p>
      </div>

      {/* The Timeline */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-6">Attack Timeline</h4>
        <div className="space-y-4">
          {/* Step 1 */}
          <div className="border-l-4 border-cyan-400 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-cyan-400 text-cyber-dark rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">1</div>
              <div className="flex-1">
                <p className="text-cyan-300 font-bold">User runs su /usr/bin/su</p>
                <p className="text-gray-300 text-sm">The kernel loads /usr/bin/su into the page cache</p>
              </div>
            </div>
          </div>

          {/* Step 2 */}
          <div className="border-l-4 border-pink-400 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-pink-400 text-cyber-dark rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">2</div>
              <div className="flex-1">
                <p className="text-pink-300 font-bold">Attacker calls splice()</p>
                <p className="text-gray-300 text-sm">Attaches the page cache page as a fragment in an SKB</p>
                <p className="text-gray-400 text-xs mt-1">Kernel correctly sets: SKBFL_SHARED_FRAG = 1</p>
              </div>
            </div>
          </div>

          {/* Step 3 */}
          <div className="border-l-4 border-purple-400 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-purple-400 text-cyber-dark rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">3</div>
              <div className="flex-1">
                <p className="text-purple-300 font-bold">Attacker sends malicious packets</p>
                <p className="text-gray-300 text-sm">Crafted as ESP-encrypted data pointing to this SKB</p>
              </div>
            </div>
          </div>

          {/* Step 4 */}
          <div className="border-l-4 border-red-400 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-red-400 text-cyber-dark rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">4</div>
              <div className="flex-1">
                <p className="text-red-300 font-bold">skb_try_coalesce() bug</p>
                <p className="text-gray-300 text-sm">When merging SKBs, SKBFL_SHARED_FRAG flag is lost</p>
                <p className="text-red-400 text-xs mt-1">← The critical bug happens here!</p>
              </div>
            </div>
          </div>

          {/* Step 5 */}
          <div className="border-l-4 border-orange-400 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-orange-400 text-cyber-dark rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">5</div>
              <div className="flex-1">
                <p className="text-orange-300 font-bold">esp_input() decryption</p>
                <p className="text-gray-300 text-sm">Checks: is SKBFL_SHARED_FRAG set? NO!</p>
                <p className="text-gray-400 text-xs mt-1">Kernel thinks: "safe to modify in place"</p>
              </div>
            </div>
          </div>

          {/* Step 6 */}
          <div className="border-l-4 border-yellow-400 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-yellow-400 text-cyber-dark rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">6</div>
              <div className="flex-1">
                <p className="text-yellow-300 font-bold">In-place AES-GCM decryption</p>
                <p className="text-gray-300 text-sm">Decrypts into the page cache directly</p>
                <p className="text-red-400 text-xs mt-1">✗ /usr/bin/su is now corrupted!</p>
              </div>
            </div>
          </div>

          {/* Step 7 */}
          <div className="border-l-4 border-red-600 pl-4 py-3">
            <div className="flex items-start gap-3">
              <div className="bg-red-600 text-white rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 font-bold text-sm">7</div>
              <div className="flex-1">
                <p className="text-red-300 font-bold">Privilege escalation</p>
                <p className="text-gray-300 text-sm">Attacker runs `su` again, executes their injected code</p>
                <p className="text-red-400 text-xs mt-1">✗ Code runs with root privileges!</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* The Bug Root Cause */}
      <div className="cyber-panel rounded-lg p-6 border-2 border-red-500 bg-red-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-red-400 mb-4">🔴 The Root Cause</h4>
        <p className="text-gray-200 text-sm mb-4">
          A security patch added <span className="font-bold">SKBFL_SHARED_FRAG</span> flag to prevent a different memory corruption issue (called the Dirty Frag vulnerability). However, the patch missed the fact that <span className="font-bold">skb_try_coalesce()</span> could lose this flag.
        </p>
        <div className="bg-red-900 bg-opacity-30 rounded p-3 text-red-300 text-xs border border-red-700">
          <p className="font-bold mb-2">The classic security paradox:</p>
          <p>
            A security patch meant to fix one bug inadvertently created another by not preserving a critical flag during packet coalescing. This led to a false sense of safety when in-place modifications were performed on shared memory.
          </p>
        </div>
      </div>

      {/* Why This Works */}
      <div className="cyber-panel rounded-lg p-6 border border-cyan-400 border-opacity-30">
        <h4 className="text-lg font-bold text-cyan-400 mb-4">💥 Why This Attack Works</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-black bg-opacity-50 rounded p-4">
            <p className="text-cyan-300 font-bold text-sm mb-3">Layers of Exploitation</p>
            <ol className="text-gray-300 text-xs space-y-2">
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>Page cache (shared memory)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>Socket buffers (network path)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>splice() (efficient attachment)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>Coalesce bug (flag loss)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>In-place AES-GCM (arbitrary write)</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>SETUID binary (privilege escalation)</span>
              </li>
            </ol>
          </div>

          <div className="bg-black bg-opacity-50 rounded p-4">
            <p className="text-pink-300 font-bold text-sm mb-3">The Checklist</p>
            <div className="space-y-2 text-gray-300 text-xs">
              <div className="flex items-center gap-2">
                <span className="text-green-400">✓</span>
                <span>Attacker can send custom packets (UDP/TCP)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-400">✓</span>
                <span>Page cache is shared (reading files)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-400">✓</span>
                <span>splice() is available (most systems)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-400">✓</span>
                <span>Coalesce can lose the flag (bug!)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-400">✓</span>
                <span>Kernel will decrypt in-place (trusts flag)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-green-400">✓</span>
                <span>SETUID binaries exist (su, sudo, etc.)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* The Mental Model */}
      <div className="cyber-panel rounded-lg p-6 border border-green-500 border-opacity-30 bg-green-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-green-400 mb-3">💡 Mental Model</h4>
        <p className="text-gray-200 text-sm leading-relaxed">
          <span className="font-bold">The flag is like a warning sticker.</span> When properly set, it says: "⚠️ This memory is shared—copy before modifying." When the kernel sees the flag, it copies first, keeping the original safe.
        </p>
        <p className="text-gray-200 text-sm leading-relaxed mt-3">
          <span className="font-bold">skb_try_coalesce() accidentally removed the sticker</span> while the memory was still shared. Later, the kernel saw no sticker, assumed the memory was private, and modified it in place.
        </p>
        <p className="text-gray-200 text-sm leading-relaxed mt-3">
          <span className="font-bold">The attacker exploited this by using the page cache:</span> By attaching a file's cached page and then triggering the coalesce bug, they forced the kernel to decrypt malicious data directly into that page. Since every other process reads from the same cache, they all see the modified file.
        </p>
      </div>

      {/* Summary Box */}
      <div className="cyber-panel rounded-lg p-8 border-2 border-cyber-cyan bg-cyber-cyan bg-opacity-5">
        <h4 className="text-xl font-bold text-cyber-cyan mb-6">🎓 Summary: Fragnesia</h4>
        <p className="text-gray-200 text-sm leading-relaxed mb-4">
          <span className="font-bold">What happened:</span> A bug in skb_try_coalesce() lost the SKBFL_SHARED_FRAG flag. This flag tells the kernel that a fragment's memory is shared with the page cache and should not be modified in-place. When the flag was lost, the kernel thought it was safe to decrypt ESP packets in-place into that memory. But the memory was actually the page cache copy of /usr/bin/su, which is read by every process.
        </p>
        <p className="text-gray-200 text-sm leading-relaxed mb-4">
          <span className="font-bold">The attack:</span> An attacker crafted malicious ESP-encrypted packets, attached a page cache page as a fragment, and sent the packets. When the kernel processed them, it decrypted the attacker's controlled ciphertext directly into the /usr/bin/su cache page, corrupting the binary.
        </p>
        <p className="text-gray-200 text-sm leading-relaxed">
          <span className="font-bold">The result:</span> When any user (including root through sudo) ran the corrupted su binary, they executed the attacker's code with elevated privileges, achieving privilege escalation.
        </p>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Concepts Recap:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">Page cache:</span> Shared RAM copy of file data</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">Fragment:</span> Piece of an SKB, often pointing to a page</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">Flag:</span> Boolean marker controlling kernel behavior</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">SKBFL_SHARED_FRAG:</span> "Don't modify in-place, copy first"</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">Coalesce bug:</span> Lost the flag during SKB merge</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">In-place decryption:</span> Writes plaintext to same memory</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span><span className="font-bold">Result:</span> Arbitrary writes to page cache → privilege escalation</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
