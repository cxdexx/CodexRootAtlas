import { useState } from 'react'

export default function ByteWriteVisual() {
  const [numWrites, setNumWrites] = useState(0)
  const [currentByte, setCurrentByte] = useState(0)

  const maxWrites = 8
  const suBinaryStart = [0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]

  const handleAddWrite = () => {
    if (numWrites < maxWrites) {
      setNumWrites(numWrites + 1)
      setCurrentByte((currentByte + 1) % suBinaryStart.length)
    }
  }

  const handleReset = () => {
    setNumWrites(0)
    setCurrentByte(0)
  }

  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">📝 One-Byte Write Visualization</h3>
        <p className="text-gray-200 mb-4">
          Once the attacker can write to the page cache, they write byte-by-byte (or word-by-word) by controlling the plaintext from decryption.
        </p>
        <p className="text-gray-200">
          Even 1-byte modifications can be powerful—changing a single instruction or permission bit.
        </p>
      </div>

      {/* Memory Representation */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">Page Cache Memory: /usr/bin/su</h4>
        <div className="bg-black bg-opacity-50 rounded p-6 mb-6">
          <p className="text-gray-400 text-xs mb-4">First 8 bytes (ELF header):</p>
          <div className="flex gap-2 flex-wrap">
            {suBinaryStart.map((byte, idx) => {
              const isModified = idx < numWrites
              return (
                <div
                  key={idx}
                  className={`memory-cell ${isModified ? 'modified' : ''} transition-all ${
                    idx === currentByte && numWrites < maxWrites ? 'animate-pulse' : ''
                  }`}
                >
                  <div>
                    <div className="text-xs font-bold">{byte.toString(16).toUpperCase().padStart(2, '0')}</div>
                    {isModified && (
                      <div className="text-xs text-pink-300 mt-1">✓</div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
          <p className="text-gray-400 text-xs mt-4">
            0x7F 0x45 0x4C 0x46 = ELF magic number (marks this as executable)
          </p>
        </div>

        {/* What's Being Modified */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-green-900 bg-opacity-30 rounded p-4 border border-green-600">
            <p className="text-green-300 font-bold text-sm mb-2">Original (Safe)</p>
            <div className="font-mono text-xs text-gray-300">
              <p>7F 45 4C 46 02 01 01 00</p>
              <p className="text-green-400 mt-2">Valid ELF 64-bit executable</p>
            </div>
          </div>

          <div className="bg-red-900 bg-opacity-30 rounded p-4 border border-red-600">
            <p className="text-red-300 font-bold text-sm mb-2">After {numWrites} Writes (Corrupted)</p>
            <div className="font-mono text-xs text-gray-300">
              <p>
                {suBinaryStart.map((byte, idx) => {
                  const modifiedByte = idx < numWrites ? Math.floor(Math.random() * 256) : byte
                  return (
                    <span key={idx} className={idx < numWrites ? 'text-red-400' : 'text-gray-300'}>
                      {modifiedByte.toString(16).toUpperCase().padStart(2, '0')}{' '}
                    </span>
                  )
                })}
              </p>
              <p className="text-red-400 mt-2">
                {numWrites === 0 ? 'Not yet corrupted' : 'File header is now corrupted!'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="cyber-panel rounded-lg p-6 border border-cyan-400 border-opacity-30">
        <h4 className="text-lg font-bold text-cyan-400 mb-4">Simulate Byte Writes</h4>
        <div className="space-y-4">
          <div className="flex gap-3">
            <button
              onClick={handleAddWrite}
              disabled={numWrites >= maxWrites}
              className="flex-1 cyber-button disabled:opacity-50"
            >
              Write Next Byte
            </button>
            <button
              onClick={handleReset}
              className="cyber-button"
            >
              Reset
            </button>
          </div>

          <div className="bg-black bg-opacity-50 rounded p-4">
            <p className="text-gray-300 text-sm mb-2">Progress</p>
            <div className="w-full bg-gray-700 rounded-full h-3">
              <div
                className="bg-gradient-to-r from-cyber-pink to-purple-600 h-3 rounded-full transition-all"
                style={{ width: `${(numWrites / maxWrites) * 100}%` }}
              />
            </div>
            <p className="text-gray-400 text-xs mt-2">{numWrites} / {maxWrites} writes</p>
          </div>
        </div>
      </div>

      {/* Attack Scenario */}
      <div className="cyber-panel rounded-lg p-6 border border-yellow-500 border-opacity-30 bg-yellow-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-yellow-400 mb-4">💡 Why 1-Byte Writes Matter</h4>
        <div className="space-y-3 text-gray-200 text-sm">
          <div className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">1.</span>
            <div>
              <p className="font-bold">Modify permissions</p>
              <p className="text-gray-400 text-xs">Change +x bit on an executable</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">2.</span>
            <div>
              <p className="font-bold">Change syscall number</p>
              <p className="text-gray-400 text-xs">Replace a few bytes to call a different syscall</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">3.</span>
            <div>
              <p className="font-bold">Patch security checks</p>
              <p className="text-gray-400 text-xs">Disable privilege checks by changing a comparison</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">4.</span>
            <div>
              <p className="font-bold">Build larger changes over time</p>
              <p className="text-gray-400 text-xs">Multiple packets = multiple writes = full exploit</p>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Flow */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-cyan mb-4">Attack Flow</h4>
        <ol className="space-y-3 text-gray-200 text-sm">
          <li className="flex items-start gap-3">
            <span className="bg-cyber-cyan text-cyber-dark rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 font-bold">1</span>
            <span>Attacker sends malicious ESP-encrypted packet #1</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="bg-cyber-cyan text-cyber-dark rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 font-bold">2</span>
            <span>esp_input() decrypts it in-place into page cache (1 byte written)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="bg-cyber-cyan text-cyber-dark rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 font-bold">3</span>
            <span>Attacker sends packet #2 (writes next byte)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="bg-cyber-cyan text-cyber-dark rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 font-bold">4</span>
            <span>Repeat until /usr/bin/su is fully corrupted with attacker's code</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="bg-cyber-cyan text-cyber-dark rounded-full w-6 h-6 flex items-center justify-center flex-shrink-0 font-bold">5</span>
            <span>Next time anyone runs `su`, they execute attacker's code (with root privileges!)</span>
          </li>
        </ol>
      </div>

      {/* Exploitation Example */}
      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// Conceptual attack flow (no real exploit code)</p>
        <pre className="text-cyan-400">{`// Attacker-controlled loop:
for (byte_offset = 0; byte_offset < target_size; byte_offset++) {
  // Create ESP-encrypted packet
  // Ciphertext = desired_byte ⊕ keystream
  pkt = create_esp_packet(
    crafted_ciphertext,
    src_ip, dst_ip,
    fragment_offset = byte_offset
  );
  
  // Send packet
  send(pkt);
  
  // Kernel path:
  // recv() -> esp_input_decrypt(pkt)
  //        -> (SKBFL_SHARED_FRAG == 0)
  //        -> aes_gcm_decrypt(page_cache + offset)
  //        -> page_cache[offset] now holds desired_byte
}

// Result: /usr/bin/su is now attacker's code!
// Next: $ su → executes attacker code as root
`}</pre>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Each malicious packet can write bytes to the page cache</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Attacker controls the plaintext (via ciphertext and keystream)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>1-byte changes can disable security checks</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Full exploit: Corrupt /usr/bin/su to run attacker's code</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
