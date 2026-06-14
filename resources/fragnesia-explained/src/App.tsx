import { useState } from 'react'
import PageCacheExplainer from './components/PageCacheExplainer'
import SocketBufferExplainer from './components/SocketBufferExplainer'
import FragmentExplainer from './components/FragmentExplainer'
import FlagExplainer from './components/FlagExplainer'
import SharedFragExplainer from './components/SharedFragExplainer'
import CoalesceVisualizer from './components/CoalesceVisualizer'
import SafeVsUnsafePath from './components/SafeVsUnsafePath'
import AESGCMAnimation from './components/AESGCMAnimation'
import ByteWriteVisual from './components/ByteWriteVisual'
import SummaryPanel from './components/SummaryPanel'
import QuizSection from './components/QuizSection'

function App() {
  const [activeSection, setActiveSection] = useState(0)

  const sections = [
    { title: 'What is the Page Cache?', component: PageCacheExplainer },
    { title: 'What is a Socket Buffer?', component: SocketBufferExplainer },
    { title: 'What is a Fragment?', component: FragmentExplainer },
    { title: 'What is a Flag?', component: FlagExplainer },
    { title: 'SKBFL_SHARED_FRAG Flag', component: SharedFragExplainer },
    { title: 'skb_try_coalesce() Function', component: CoalesceVisualizer },
    { title: 'Safe vs Unsafe Paths', component: SafeVsUnsafePath },
    { title: 'AES-GCM In-Place Decryption', component: AESGCMAnimation },
    { title: 'One-Byte Write Visualization', component: ByteWriteVisual },
    { title: 'The Full Picture', component: SummaryPanel },
    { title: 'Test Your Knowledge', component: QuizSection },
  ]

  const CurrentComponent = sections[activeSection].component

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-darker via-cyber-dark to-gray-900">
      {/* Header */}
      <header className="sticky top-0 z-40 border-b border-cyber-purple border-opacity-20 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
          <h1 className="text-4xl font-bold cyber-glow text-transparent bg-clip-text bg-gradient-to-r from-cyber-purple via-cyber-pink to-cyber-cyan">
            🔐 Fragnesia Explained
          </h1>
          <p className="text-gray-400 text-lg mt-2">Understanding Linux Kernel Memory Corruption</p>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar Navigation */}
          <div className="lg:col-span-1">
            <nav className="cyber-panel rounded-lg p-4 sticky top-24 max-h-[calc(100vh-120px)] overflow-y-auto">
              <h2 className="text-lg font-bold text-cyber-cyan mb-4">Sections</h2>
              <ul className="space-y-2">
                {sections.map((section, index) => (
                  <li key={index}>
                    <button
                      onClick={() => setActiveSection(index)}
                      className={`w-full text-left px-3 py-2 rounded transition-all duration-300 text-sm font-medium ${
                        activeSection === index
                          ? 'bg-cyber-purple text-white cyber-glow'
                          : 'text-gray-300 hover:bg-cyber-purple hover:bg-opacity-20'
                      }`}
                    >
                      {section.title}
                    </button>
                  </li>
                ))}
              </ul>
              <div className="mt-6 pt-6 border-t border-cyber-purple border-opacity-20">
                <p className="text-xs text-gray-400">Progress: {activeSection + 1} of {sections.length}</p>
                <div className="w-full bg-gray-700 rounded-full h-2 mt-2">
                  <div
                    className="bg-gradient-to-r from-cyber-purple to-cyber-pink h-2 rounded-full transition-all duration-500"
                    style={{ width: `${((activeSection + 1) / sections.length) * 100}%` }}
                  ></div>
                </div>
              </div>
            </nav>
          </div>

          {/* Main Content Area */}
          <div className="lg:col-span-3">
            <div className="cyber-panel rounded-lg p-8 min-h-[600px]">
              <h2 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan to-cyber-purple mb-6">
                {sections[activeSection].title}
              </h2>
              <div className="animate-fade-in">
                <CurrentComponent />
              </div>
            </div>

            {/* Navigation Buttons */}
            <div className="flex justify-between mt-6">
              <button
                onClick={() => setActiveSection(Math.max(0, activeSection - 1))}
                disabled={activeSection === 0}
                className="cyber-button disabled:opacity-50 disabled:cursor-not-allowed"
              >
                ← Previous
              </button>
              <button
                onClick={() => setActiveSection(Math.min(sections.length - 1, activeSection + 1))}
                disabled={activeSection === sections.length - 1}
                className="cyber-button disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-cyber-purple border-opacity-20 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>Educational Resource • Fragnesia (CVE-2024-0604) • For Learning Purposes Only</p>
        </div>
      </footer>
    </div>
  )
}

export default App
