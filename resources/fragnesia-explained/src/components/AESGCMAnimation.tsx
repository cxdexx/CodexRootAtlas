import { useState } from 'react'

export default function AESGCMAnimation() {
  const [step, setStep] = useState(0)

  const steps = [
    {
      title: 'What is AES-GCM?',
      description: 'AES-GCM is a cipher used for IPsec ESP (Encapsulating Security Payload). It encrypts data and produces a ciphertext.',
    },
    {
      title: 'In-Place Decryption Concept',
      description: 'To decrypt, AES-GCM generates a keystream and XORs it with the ciphertext: plaintext = ciphertext ⊕ keystream',
    },
    {
      title: 'The Problem: In-Place XOR',
      description: 'The kernel often decrypts in-place: it reads the ciphertext from memory, XORs it with the keystream, and writes plaintext back to the same memory location.',
    },
    {
      title: 'If Memory is Page Cache...',
      description: 'If the memory being decrypted points to the page cache, the plaintext overwrites the original file data. This is the attack vector.',
    },
  ]

  const currentStep = steps[step]

  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🔐 AES-GCM In-Place Decryption</h3>
        <p className="text-gray-200">
          AES-GCM is the encryption algorithm used in IPsec ESP. The kernel decrypts it "in-place", which means writing the plaintext directly into the same memory location as the ciphertext.
        </p>
      </div>

      {/* Step Navigation */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">{currentStep.title}</h4>
        <p className="text-gray-200 text-sm mb-6">{currentStep.description}</p>

        <div className="space-y-6">
          {step === 0 && (
            <div className="space-y-3">
              <div className="bg-black bg-opacity-50 rounded p-4 border-l-4 border-cyber-cyan">
                <p className="text-gray-300 text-sm">
                  ESP (Encapsulating Security Payload) encrypts traffic using AES-GCM. On the receiver side, the kernel must decrypt.
                </p>
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div className="text-center">
                  <div className="bg-cyber-cyan bg-opacity-20 rounded p-3 mb-2 font-mono text-xs text-cyan-300">
                    Algorithm: AES-256-GCM
                  </div>
                </div>
                <div className="text-center">
                  <div className="bg-cyber-pink bg-opacity-20 rounded p-3 mb-2 font-mono text-xs text-pink-300">
                    Key: (secret)
                  </div>
                </div>
                <div className="text-center">
                  <div className="bg-purple-500 bg-opacity-20 rounded p-3 mb-2 font-mono text-xs text-purple-300">
                    IV: Initialization Vector
                  </div>
                </div>
              </div>
            </div>
          )}

          {step === 1 && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-3">
                {/* Ciphertext */}
                <div className="border border-cyber-cyan rounded p-4 bg-cyber-cyan bg-opacity-5">
                  <p className="text-cyan-300 font-bold text-sm mb-2">Ciphertext (encrypted data)</p>
                  <div className="font-mono text-xs text-cyan-400">
                    A3F2 7E19 B4C8 2D91 5F73 8A46 E2C1 9B75
                  </div>
                </div>

                {/* Keystream */}
                <div className="border border-cyber-pink rounded p-4 bg-cyber-pink bg-opacity-5">
                  <p className="text-pink-300 font-bold text-sm mb-2">Keystream (generated from key + IV)</p>
                  <div className="font-mono text-xs text-pink-400">
                    5D8E 1A72 3B94 C6F5 E8B2 7C4A 6F3D 2A8C
                  </div>
                </div>

                {/* XOR Operation */}
                <div className="text-center py-2">
                  <p className="text-gray-400 text-sm">↓</p>
                  <p className="text-gray-300 font-bold">XOR Operation (⊕)</p>
                  <p className="text-gray-400 text-sm">↓</p>
                </div>

                {/* Plaintext */}
                <div className="border border-green-500 rounded p-4 bg-green-500 bg-opacity-5">
                  <p className="text-green-300 font-bold text-sm mb-2">Plaintext (original data)</p>
                  <div className="font-mono text-xs text-green-400">
                    FE7C 649D 8A7C F664 B981 F68C 87FB B951
                  </div>
                </div>
              </div>

              <div className="bg-blue-900 bg-opacity-30 rounded p-3 text-blue-300 text-xs border border-blue-600">
                <p>Formula: plaintext = ciphertext ⊕ keystream</p>
                <p className="mt-1">This is reversible: you can also do ciphertext = plaintext ⊕ keystream</p>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              <div className="space-y-3">
                <p className="text-gray-200 text-sm">
                  To save memory, the kernel often decrypts "in-place":
                </p>

                <div className="border border-cyan-400 rounded p-4 bg-cyan-400 bg-opacity-5">
                  <p className="text-cyan-300 font-bold text-sm mb-3">In-Place Decryption Process</p>
                  <ol className="text-gray-300 text-xs space-y-2">
                    <li className="flex items-start gap-2">
                      <span className="text-cyan-400 font-bold">1.</span>
                      <span>Memory holds ciphertext: [A3F2 7E19 ...]</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-cyan-400 font-bold">2.</span>
                      <span>Generate keystream in CPU</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-cyan-400 font-bold">3.</span>
                      <span>XOR: ciphertext ⊕ keystream = plaintext</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-cyan-400 font-bold">4.</span>
                      <span>Write plaintext BACK to same memory location</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-cyan-400 font-bold">5.</span>
                      <span>Now memory holds plaintext: [FE7C 649D ...]</span>
                    </li>
                  </ol>
                </div>

                <div className="bg-yellow-900 bg-opacity-30 rounded p-3 text-yellow-300 text-xs border border-yellow-600">
                  <p className="font-bold">Why in-place?</p>
                  <p>Faster (no extra allocation), uses less memory. Only works if you're sure no one else is reading that memory.</p>
                </div>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4">
              <div className="border-l-4 border-red-500 bg-red-900 bg-opacity-20 rounded p-4 text-red-300">
                <p className="font-bold mb-2">🚨 The Attack Works Because:</p>
                <ol className="text-sm space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="font-bold">1.</span>
                    <span>Attacker uses splice() to attach /usr/bin/su page cache page as a fragment</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="font-bold">2.</span>
                    <span>They craft malicious ESP-encrypted packets pointing to it</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="font-bold">3.</span>
                    <span>Kernel receives packets, coalesce removes the SKBFL_SHARED_FRAG flag</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="font-bold">4.</span>
                    <span>esp_input() sees flag = 0, thinks it's safe to decrypt in-place</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="font-bold">5.</span>
                    <span>Decrypts the controlled ciphertext "in-place" into the /usr/bin/su page</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="font-bold">6.</span>
                    <span>Now /usr/bin/su in page cache is corrupted with attacker's data</span>
                  </li>
                </ol>
              </div>

              <div className="bg-green-900 bg-opacity-20 rounded p-3 border-l-4 border-green-500 text-green-300 text-sm">
                <p className="font-bold">The Genius of the Attack:</p>
                <p>
                  By controlling the encrypted data AND knowing it will be decrypted in-place into the page cache, the attacker can write arbitrary bytes to the page cache—effectively writing arbitrary code into /usr/bin/su.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Step Navigation */}
      <div className="flex gap-4 items-center justify-center">
        <button
          onClick={() => setStep(Math.max(0, step - 1))}
          disabled={step === 0}
          className="cyber-button disabled:opacity-50"
        >
          ← Previous
        </button>
        <div className="flex gap-2">
          {steps.map((_, index) => (
            <button
              key={index}
              onClick={() => setStep(index)}
              className={`w-3 h-3 rounded-full transition-all ${
                index === step ? 'bg-cyber-pink scale-150' : 'bg-gray-600'
              }`}
            />
          ))}
        </div>
        <button
          onClick={() => setStep(Math.min(steps.length - 1, step + 1))}
          disabled={step === steps.length - 1}
          className="cyber-button disabled:opacity-50"
        >
          Next →
        </button>
      </div>

      <div className="text-center text-gray-400 text-sm">
        Step {step + 1} of {steps.length}
      </div>

      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// Simplified in-place decryption</p>
        <pre className="text-cyan-400">{`int esp_input_decrypt(struct sk_buff *skb) {
  struct skb_frag_t *frag = &skb->frags[0];
  
  // This is the KEY decision point:
  if (skb->flags & SKBFL_SHARED_FRAG) {
    // Safe path: Copy first
    void *buf = kmalloc(frag->size);
    memcpy(buf, frag->data, frag->size);
    
    // Decrypt into copy
    aes_gcm_decrypt(buf, key, iv);
    
    // Write back to new location
    frag->data = buf;
  } else {
    // UNSAFE: Decrypt in-place
    aes_gcm_decrypt(frag->data, key, iv);
    // ^ If frag->data points to page cache,
    // ^ the file is now corrupted!
  }
  
  return 0;
}
`}</pre>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>AES-GCM decrypts by XORing ciphertext with keystream</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>In-place decryption writes plaintext back to same memory</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>If that memory is page cache, the file gets modified</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Attacker controls the ciphertext (via malicious packets)</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
