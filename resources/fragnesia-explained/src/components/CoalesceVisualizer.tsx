import { useState } from 'react'

export default function CoalesceVisualizer() {
  const [step, setStep] = useState(0)

  const steps = [
    {
      title: 'Initial State: Two SKBs',
      description: 'We have two socket buffers arriving separately from the network.',
      showBefore: true,
    },
    {
      title: 'Merge Fragments',
      description: 'skb_try_coalesce() tries to combine fragments from both SKBs into one.',
      showBefore: true,
    },
    {
      title: 'Flag is Cleared!',
      description: 'After coalesce, SKBFL_SHARED_FRAG is lost, even though the fragment still points to shared page cache.',
      showBefore: false,
    },
    {
      title: 'The Problem',
      description: 'Now esp_input() sees SHARED_FRAG = 0 and thinks it can modify in place. But it\'s modifying page cache!',
      showBefore: false,
    },
  ]

  const currentStep = steps[step]

  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🔀 skb_try_coalesce(): The Problematic Function</h3>
        <p className="text-gray-200">
          <span className="font-bold">skb_try_coalesce()</span> is an optimization that merges two socket buffers into one. However, a bug in this function loses track of the <span className="font-bold text-cyber-pink">SKBFL_SHARED_FRAG</span> flag.
        </p>
      </div>

      {/* Step Visualization */}
      <div className="cyber-panel rounded-lg p-8 border border-cyber-purple border-opacity-30">
        <div className="mb-6">
          <h4 className="text-xl font-bold text-cyber-cyan mb-2">{currentStep.title}</h4>
          <p className="text-gray-200">{currentStep.description}</p>
        </div>

        <div className="space-y-8">
          {/* Before State */}
          {currentStep.showBefore && (
            <div>
              <h5 className="text-lg font-bold text-cyber-pink mb-4">Before Coalesce</h5>
              <div className="grid grid-cols-2 gap-4">
                {/* SKB 1 */}
                <div className="border border-cyan-400 rounded p-4 bg-cyan-400 bg-opacity-5">
                  <p className="text-cyan-400 font-bold mb-3">SKB 1</p>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-10 border-2 border-cyan-400 rounded flex items-center justify-center text-xs font-mono">Frag</div>
                      <div className="flex-1">
                        <p className="text-gray-300 text-xs">Page Cache</p>
                        <div className="flag-badge active">SHARED_FRAG=1</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* SKB 2 */}
                <div className="border border-pink-400 rounded p-4 bg-pink-400 bg-opacity-5">
                  <p className="text-pink-400 font-bold mb-3">SKB 2</p>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-10 border-2 border-pink-400 rounded flex items-center justify-center text-xs font-mono">Frag</div>
                      <div className="flex-1">
                        <p className="text-gray-300 text-xs">Page Cache</p>
                        <div className="flag-badge active">SHARED_FRAG=1</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* After State */}
          {!currentStep.showBefore && (
            <div>
              <h5 className="text-lg font-bold text-red-400 mb-4">After Coalesce</h5>
              <div className="border border-red-500 rounded p-4 bg-red-500 bg-opacity-10">
                <p className="text-red-400 font-bold mb-3">Combined SKB (or SKB 1 after merge)</p>
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-10 border-2 border-red-400 rounded flex items-center justify-center text-xs font-mono">Frag</div>
                    <div className="flex-1">
                      <p className="text-gray-300 text-xs">Page Cache</p>
                      <div className="flag-badge inactive">SHARED_FRAG=0 ❌</div>
                      <p className="text-red-400 text-xs mt-1">← Flag mysteriously disappeared!</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-10 border-2 border-red-400 rounded flex items-center justify-center text-xs font-mono">Frag</div>
                    <div className="flex-1">
                      <p className="text-gray-300 text-xs">Page Cache</p>
                      <div className="flag-badge inactive">SHARED_FRAG=0 ❌</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Code Example */}
      <div className="code-block">
        <p className="text-gray-400 text-xs mb-2">// Simplified skb_try_coalesce() bug</p>
        <pre className="text-cyan-400">{`int skb_try_coalesce(struct sk_buff *to, struct sk_buff *from) {
  // Try to merge fragments
  
  // BUG: When copying shinfo, the SKBFL_SHARED_FRAG
  // flag from 'from' SKB isn't preserved!
  
  struct skb_shared_info *from_shinfo = skb_shinfo(from);
  struct skb_shared_info *to_shinfo = skb_shinfo(to);
  
  // Copy fragments without preserving ALL flags
  for (i = 0; i < from_shinfo->nr_frags; i++) {
    to_shinfo->frags[to_shinfo->nr_frags++] = 
      from_shinfo->frags[i];
  }
  
  // PROBLEM: to_shinfo->flags might not have
  // SKBFL_SHARED_FRAG set, even though the
  // fragments still point to page cache!
  
  return 0;
}
`}</pre>
      </div>

      {/* What Happens Next */}
      <div className="cyber-panel rounded-lg p-6 border border-yellow-500 border-opacity-30 bg-yellow-500 bg-opacity-5">
        <h4 className="text-lg font-bold text-yellow-400 mb-3">⚠️ What Happens Next</h4>
        <ol className="text-gray-200 text-sm space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">1.</span>
            <span>esp_input() (IPsec decryption) receives this SKB</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">2.</span>
            <span>It checks: is SKBFL_SHARED_FRAG set?</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">3.</span>
            <span>Answer: NO (the flag was lost!)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">4.</span>
            <span>It decrypts in place, modifying the page cache</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-yellow-400 font-bold">5.</span>
            <span>The /usr/bin/su binary in the page cache is corrupted</span>
          </li>
        </ol>
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

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>skb_try_coalesce() merges two SKBs into one</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>The bug: SKBFL_SHARED_FRAG flag is lost during merge</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>But the fragments still point to page cache!</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Later code believes the flag and modifies in place</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
