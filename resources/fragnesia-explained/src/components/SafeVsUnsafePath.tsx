import { useState } from 'react'

export default function SafeVsUnsafePath() {
  const [sharedFrag, setSharedFrag] = useState(1)
  const [modified, setModified] = useState(false)

  const handleToggle = () => {
    setSharedFrag(sharedFrag === 1 ? 0 : 1)
    setModified(false)
  }

  const handleModify = () => {
    setModified(true)
  }

  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">🛤️ Safe vs Unsafe Modification Paths</h3>
        <p className="text-gray-200">
          When the kernel wants to modify data in a fragment, it makes a choice based on the <span className="font-bold">SKBFL_SHARED_FRAG</span> flag:
        </p>
      </div>

      {/* Flag Toggle */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">Current Flag State</h4>
        <div className="flex items-center gap-4 mb-6">
          <button
            onClick={handleToggle}
            className={`px-6 py-3 rounded font-bold transition-all ${
              sharedFrag === 1
                ? 'bg-green-600 text-white border-2 border-green-400'
                : 'bg-red-600 text-white border-2 border-red-400'
            }`}
          >
            {sharedFrag === 1 ? '✓ SKBFL_SHARED_FRAG = 1' : '✗ SKBFL_SHARED_FRAG = 0'}
          </button>
          <p className="text-gray-300 text-sm">Click to toggle flag</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Safe Path */}
        <div className="cyber-panel rounded-lg p-6 border-2 border-green-500 bg-green-500 bg-opacity-5">
          <h4 className="text-lg font-bold text-green-400 mb-4">✓ SAFE PATH</h4>
          <p className="text-gray-200 text-sm mb-4">
            <span className="font-bold">When SKBFL_SHARED_FRAG = 1</span>
          </p>

          <div className="space-y-3 mb-6">
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className="font-mono text-green-300 text-xs mb-2">Step 1: Detect shared memory</p>
              <p className="text-gray-300 text-xs">if (flags & SKBFL_SHARED_FRAG)</p>
            </div>
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className="font-mono text-green-300 text-xs mb-2">Step 2: Copy to new page</p>
              <p className="text-gray-300 text-xs">new_page = alloc_page()</p>
              <p className="text-gray-300 text-xs">copy_data(old_page, new_page)</p>
            </div>
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className="font-mono text-green-300 text-xs mb-2">Step 3: Update fragment</p>
              <p className="text-gray-300 text-xs">{"frag->page = new_page"}</p>
            </div>
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className="font-mono text-green-300 text-xs mb-2">Step 4: Modify the copy</p>
              <p className="text-gray-300 text-xs">esp_input_decrypt(new_page)</p>
            </div>
          </div>

          <div className="bg-green-900 bg-opacity-30 rounded p-3 border border-green-600">
            <p className="text-green-300 font-bold text-sm">✓ Result: Page cache unchanged</p>
            <p className="text-gray-300 text-xs">Other processes still see correct file data</p>
          </div>
        </div>

        {/* Unsafe Path */}
        <div className={`cyber-panel rounded-lg p-6 border-2 transition-all ${
          sharedFrag === 0
            ? 'border-red-500 bg-red-500 bg-opacity-5'
            : 'border-gray-600 bg-gray-600 bg-opacity-5 opacity-60'
        }`}>
          <h4 className={`text-lg font-bold mb-4 ${
            sharedFrag === 0 ? 'text-red-400' : 'text-gray-400'
          }`}>
            ✗ UNSAFE PATH (BUG)
          </h4>
          <p className={`text-sm mb-4 ${
            sharedFrag === 0 ? 'text-gray-200' : 'text-gray-400'
          }`}>
            <span className="font-bold">When SKBFL_SHARED_FRAG = 0</span> (incorrectly)
          </p>

          <div className="space-y-3 mb-6">
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className={`font-mono text-xs mb-2 ${
                sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
              }`}>Step 1: Check flag</p>
              <p className={`text-xs ${
                sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
              }`}>if (flags & SKBFL_SHARED_FRAG) → FALSE</p>
            </div>
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className={`font-mono text-xs mb-2 ${
                sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
              }`}>Step 2: Assume safe, no copy</p>
              <p className={`text-xs ${
                sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
              }`}>// Skip copy_data() function</p>
            </div>
            <div className="bg-black bg-opacity-50 rounded p-3">
              <p className={`font-mono text-xs mb-2 ${
                sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
              }`}>Step 3: Modify in place!</p>
              <p className={`text-xs ${
                sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
              }`}>esp_input_decrypt(original_page)</p>
            </div>
          </div>

          <div className={`rounded p-3 border ${
            sharedFrag === 0
              ? 'bg-red-900 bg-opacity-30 border-red-600'
              : 'bg-gray-700 bg-opacity-30 border-gray-600'
          }`}>
            <p className={`font-bold text-sm ${
              sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
            }`}>
              ✗ Result: Page cache CORRUPTED!
            </p>
            <p className={`text-xs ${
              sharedFrag === 0 ? 'text-red-300' : 'text-gray-400'
            }`}>
              /usr/bin/su in cache is now modified
            </p>
          </div>
        </div>
      </div>

      {/* Modification Simulation */}
      <div className="cyber-panel rounded-lg p-6 border border-cyan-400 border-opacity-30">
        <h4 className="text-lg font-bold text-cyan-400 mb-4">Simulate Modification</h4>
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <div className={`flex-1 p-4 rounded border-2 font-mono text-sm ${
              modified && sharedFrag === 0
                ? 'border-red-500 bg-red-500 bg-opacity-20 text-red-300'
                : 'border-cyan-400 bg-cyan-400 bg-opacity-10 text-cyan-300'
            }`}>
              {sharedFrag === 1 ? (
                '7F 45 4C 46 [new copy]'
              ) : (
                modified
                  ? '7F 45 4C [CORRUPTED]'
                  : '7F 45 4C 46'
              )}
            </div>
          </div>

          <button
            onClick={handleModify}
            className={`w-full py-3 rounded font-bold transition-all ${
              sharedFrag === 1
                ? 'bg-green-600 hover:bg-green-700 text-white'
                : 'bg-red-600 hover:bg-red-700 text-white'
            }`}
          >
            {sharedFrag === 1 ? '✓ Decrypt (Safe)' : '✗ Decrypt (Unsafe!)'}
          </button>

          <div className={`p-4 rounded text-sm ${
            sharedFrag === 1
              ? 'bg-green-900 bg-opacity-30 text-green-300'
              : 'bg-red-900 bg-opacity-30 text-red-300'
          }`}>
            {modified ? (
              sharedFrag === 1 ? (
                <>
                  <p className="font-bold">✓ Safe Operation Complete</p>
                  <p className="text-xs mt-1">
                    Data was copied to a new page. Page cache remains pristine.
                  </p>
                </>
              ) : (
                <>
                  <p className="font-bold">✗ CORRUPTION!</p>
                  <p className="text-xs mt-1">
                    Modification happened in place, corrupting the page cache.
                    All processes reading /usr/bin/su now see the corrupted data.
                  </p>
                </>
              )
            ) : (
              <p className="text-xs">
                {sharedFrag === 1
                  ? 'Click "Decrypt (Safe)" to see the safe path in action'
                  : 'Click "Decrypt (Unsafe!)" to demonstrate the vulnerability'}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Decision Tree */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <h4 className="text-lg font-bold text-cyber-purple mb-4">Decision Tree</h4>
        <div className="space-y-3 font-mono text-xs">
          <div className="text-gray-300">
            <p className="text-cyan-300 font-bold">if (SKBFL_SHARED_FRAG == 1)</p>
            <p className="ml-4 text-green-300">→ Take safe path (copy then modify)</p>
          </div>
          <div className="text-gray-300 mt-3">
            <p className="text-red-300 font-bold">else (SKBFL_SHARED_FRAG == 0)</p>
            <p className="ml-4 text-red-300">→ Take unsafe path (modify in place)</p>
            <p className="ml-4 text-red-400">← Bug: Flag was cleared incorrectly!</p>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <h4 className="text-lg font-bold text-cyber-cyan">Key Takeaways:</h4>
        <ul className="text-gray-200 space-y-2">
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Flag = 1: Kernel copies data before modifying (safe)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Flag = 0: Kernel modifies in place (assumes private memory)</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Fragnesia clears the flag but keeps the page shared</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="text-cyber-pink font-bold">•</span>
            <span>Result: Unsafe path corrupts the page cache</span>
          </li>
        </ul>
      </div>
    </div>
  )
}
