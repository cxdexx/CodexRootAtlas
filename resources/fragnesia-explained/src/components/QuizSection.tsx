import { useState } from 'react'

interface Question {
  id: number
  question: string
  options: string[]
  correct: number
  explanation: string
}

export default function QuizSection() {
  const [currentQ, setCurrentQ] = useState(0)
  const [selected, setSelected] = useState<number | null>(null)
  const [answered, setAnswered] = useState(false)
  const [score, setScore] = useState(0)

  const questions: Question[] = [
    {
      id: 1,
      question: 'What does SKBFL_SHARED_FRAG = 1 mean?',
      options: [
        'This fragment points to memory shared with other processes (like page cache). Copy before modifying.',
        'This fragment is private and safe to modify in place.',
        'This fragment should be discarded.',
        'This fragment is encrypted and needs decryption first.',
      ],
      correct: 0,
      explanation: 'SKBFL_SHARED_FRAG = 1 is a warning flag that tells the kernel: "This memory is shared. Make a copy before modifying it." Ignoring this flag is what led to the Fragnesia vulnerability.',
    },
    {
      id: 2,
      question: 'What function has the bug that loses the SKBFL_SHARED_FRAG flag?',
      options: [
        'esp_input() - IPsec decryption',
        'skb_try_coalesce() - SKB merging',
        'splice() - File-to-socket transfer',
        'aes_gcm_decrypt() - Encryption algorithm',
      ],
      correct: 1,
      explanation: 'skb_try_coalesce() is the function that merges two socket buffers. The bug: when copying fragments from one SKB to another, the SKBFL_SHARED_FRAG flag is not preserved. This causes the merged SKB to "forget" that its fragments are shared.',
    },
    {
      id: 3,
      question: 'Why is modifying the page cache dangerous?',
      options: [
        'It makes the system slower.',
        'It breaks networking.',
        'Every process that reads that file gets the modified version. If it\'s /usr/bin/su, all users execute the malicious code.',
        'It causes a kernel panic.',
      ],
      correct: 2,
      explanation: 'The page cache is shared: when a file is in the cache, all processes read from the same cached page. Modifying it affects every process reading that file. For critical binaries like /usr/bin/su, this enables privilege escalation.',
    },
    {
      id: 4,
      question: 'How does esp_input() decide whether to copy before modifying?',
      options: [
        'It always copies to be safe.',
        'It checks if SKBFL_SHARED_FRAG is set. If set, copy. If not, modify in place.',
        'It asks the application.',
        'It randomly chooses between copy and in-place modification.',
      ],
      correct: 1,
      explanation: 'The kernel checks the SKBFL_SHARED_FRAG flag: flag=1 → take the safe path (copy first). flag=0 → take the fast path (modify in place). In Fragnesia, the flag was wrongly cleared, so the kernel took the unsafe path.',
    },
    {
      id: 5,
      question: 'What role does splice() play in the attack?',
      options: [
        'It encrypts the malicious packets.',
        'It allows the attacker to attach a page cache page as a fragment in an SKB (initially with the flag correctly set).',
        'It performs the in-place decryption.',
        'It modifies the SKBFL_SHARED_FRAG flag directly.',
      ],
      correct: 1,
      explanation: 'splice() is a legitimate syscall that efficiently transfers data between file descriptors. The attacker uses it to attach a page cache page (/usr/bin/su) as a fragment in an SKB. Initially, the flag is correctly set, but the later coalesce bug loses it.',
    },
    {
      id: 6,
      question: 'What is "in-place" decryption in AES-GCM?',
      options: [
        'Decryption that happens on a dedicated hardware chip.',
        'Decryption that generates random output.',
        'Decryption where plaintext is written back to the same memory location as the ciphertext (no copy).',
        'Decryption that only works for local files.',
      ],
      correct: 2,
      explanation: 'In-place decryption is a memory-efficient optimization: instead of allocating new memory for the plaintext, the kernel XORs the ciphertext with a keystream and writes the plaintext back to the same location. This is fast but only safe if the memory is truly private.',
    },
    {
      id: 7,
      question: 'Why is losing a 1-byte write potentially powerful?',
      options: [
        '1 byte is too small to matter.',
        'Changing even 1 byte can alter critical instructions, permissions, or security checks. Multiple packets = multiple 1-byte writes = full exploit.',
        'Attackers can only write 1 byte total.',
        'The kernel ignores single-byte changes.',
      ],
      correct: 1,
      explanation: 'One byte is enough to change an instruction opcode, flip a permission bit, or modify a comparison. With multiple malicious packets, an attacker can build a full exploit by writing many 1-byte chunks to the page cache.',
    },
    {
      id: 8,
      question: 'What is the final result of a successful Fragnesia attack?',
      options: [
        'The system crashes.',
        'Network connection is disabled.',
        'Arbitrary code executes with the privileges of whoever runs the modified binary (often root).',
        'The system becomes very slow.',
      ],
      correct: 2,
      explanation: 'By corrupting /usr/bin/su or another SETUID binary in the page cache, the attacker ensures that whoever runs it (including root through password entry) executes the attacker\'s injected code. This is classic privilege escalation.',
    },
    {
      id: 9,
      question: 'How does the flag get lost in skb_try_coalesce()?',
      options: [
        'The attacker manually clears it via a syscall.',
        'It automatically resets every few seconds.',
        'When merging SKBs, the flags field is not properly updated to preserve the SKBFL_SHARED_FRAG bit from both fragments.',
        'The flag is never actually set, it is just assumed.',
      ],
      correct: 2,
      explanation: 'The bug is in the coalesce logic: when combining fragments from multiple SKBs, the resulting SKB\'s flags don\'t reflect all the important bits from the source SKBs. Specifically, SKBFL_SHARED_FRAG can be lost even though the fragments still point to shared memory.',
    },
    {
      id: 10,
      question: 'What is the lesson about security patches?',
      options: [
        'Security patches always fix all problems.',
        'A security patch meant to fix one bug can inadvertently create another if side effects aren\'t fully considered.',
        'Security patches are unnecessary.',
        'Only the original developers can write secure code.',
      ],
      correct: 1,
      explanation: 'Fragnesia shows a classic pattern: the SKBFL_SHARED_FRAG flag was added to fix the "Dirty Frag" bug, but the patch didn\'t account for skb_try_coalesce() losing the flag. Thorough review of all code paths is essential when adding security checks.',
    },
  ]

  const question = questions[currentQ]

  const handleAnswer = (idx: number) => {
    setSelected(idx)
    setAnswered(true)
    if (idx === question.correct) {
      setScore(score + 1)
    }
  }

  const handleNext = () => {
    if (currentQ < questions.length - 1) {
      setCurrentQ(currentQ + 1)
      setSelected(null)
      setAnswered(false)
    }
  }

  const handleReset = () => {
    setCurrentQ(0)
    setSelected(null)
    setAnswered(false)
    setScore(0)
  }

  const isComplete = currentQ === questions.length - 1 && answered

  return (
    <div className="space-y-6">
      <div className="cyber-panel rounded-lg p-6 border border-cyber-cyan border-opacity-30">
        <h3 className="text-xl font-bold text-cyber-cyan mb-4">📚 Test Your Knowledge</h3>
        <p className="text-gray-200">
          Test your understanding of Fragnesia. Answer 10 questions about the vulnerability.
        </p>
      </div>

      {/* Score Display */}
      <div className="cyber-panel rounded-lg p-6 border border-cyber-purple border-opacity-30">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-lg font-bold text-cyber-purple">Question {currentQ + 1} of {questions.length}</h4>
          <div className="text-right">
            <p className="text-cyber-cyan font-bold">{score} / {questions.length}</p>
            <p className="text-gray-400 text-xs">Correct so far</p>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-gray-700 rounded-full h-2">
          <div
            className="bg-gradient-to-r from-cyber-purple to-cyber-pink h-2 rounded-full transition-all"
            style={{ width: `${((currentQ + 1) / questions.length) * 100}%` }}
          />
        </div>
      </div>

      {/* Question Card */}
      <div className="cyber-panel rounded-lg p-8 border border-cyan-400 border-opacity-30">
        <h4 className="text-xl font-bold text-cyan-400 mb-6">{question.question}</h4>

        {/* Options */}
        <div className="space-y-3 mb-8">
          {question.options.map((option, idx) => {
            const isSelected = selected === idx
            const isCorrect = idx === question.correct
            let optionClass = 'quiz-option'

            if (answered) {
              if (isCorrect) {
                optionClass += ' correct'
              } else if (isSelected && !isCorrect) {
                optionClass += ' incorrect'
              }
            } else if (isSelected) {
              optionClass += ' selected'
            }

            return (
              <button
                key={idx}
                onClick={() => !answered && handleAnswer(idx)}
                disabled={answered}
                className={optionClass}
              >
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0 mt-1">
                    {answered && isCorrect && <span className="text-green-400 text-lg">✓</span>}
                    {answered && isSelected && !isCorrect && <span className="text-red-400 text-lg">✗</span>}
                    {!answered && <span className="text-gray-400 text-lg">{idx + 1}</span>}
                  </div>
                  <div className="text-left">
                    <p className="text-sm">{option}</p>
                  </div>
                </div>
              </button>
            )
          })}
        </div>

        {/* Explanation */}
        {answered && (
          <div className={`rounded-lg p-4 border-l-4 mb-6 ${
            selected === question.correct
              ? 'bg-green-900 bg-opacity-30 border-green-600'
              : 'bg-red-900 bg-opacity-30 border-red-600'
          }`}>
            <p className={`font-bold text-sm mb-2 ${
              selected === question.correct ? 'text-green-300' : 'text-red-300'
            }`}>
              {selected === question.correct ? '✓ Correct!' : '✗ Not quite.'}
            </p>
            <p className="text-gray-200 text-sm">{question.explanation}</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <div className="flex gap-4 justify-between">
        <button
          onClick={handleReset}
          className="cyber-button"
        >
          Reset Quiz
        </button>

        {!answered ? (
          <div className="text-gray-400 text-sm flex items-center">
            Choose an option to continue
          </div>
        ) : !isComplete ? (
          <button
            onClick={handleNext}
            className="cyber-button"
          >
            Next Question →
          </button>
        ) : (
          <div className="text-right">
            <p className="text-cyber-cyan font-bold">Quiz Complete!</p>
            <p className="text-gray-300 text-sm">
              Your Score: {score} / {questions.length} ({Math.round((score / questions.length) * 100)}%)
            </p>
          </div>
        )}
      </div>

      {/* Final Results */}
      {isComplete && (
        <div className={`cyber-panel rounded-lg p-6 border-2 ${
          score >= questions.length - 2
            ? 'border-green-500 bg-green-500 bg-opacity-5'
            : 'border-yellow-500 bg-yellow-500 bg-opacity-5'
        }`}>
          <h4 className={`text-lg font-bold mb-4 ${
            score >= questions.length - 2 ? 'text-green-400' : 'text-yellow-400'
          }`}>
            Quiz Results
          </h4>
          <div className="space-y-3 text-gray-200 text-sm">
            <p>
              {score === questions.length && (
                <>
                  <span className="text-green-400 font-bold">Perfect score!</span> You have a deep understanding of Fragnesia!
                </>
              )}
              {score >= questions.length - 2 && score < questions.length && (
                <>
                  <span className="text-green-400 font-bold">Excellent!</span> You understand the key concepts well.
                </>
              )}
              {score >= questions.length / 2 && score < questions.length - 2 && (
                <>
                  <span className="text-yellow-400 font-bold">Good job!</span> Review the sections where you had trouble.
                </>
              )}
              {score < questions.length / 2 && (
                <>
                  <span className="text-yellow-400 font-bold">Keep learning!</span> Go back and review each section carefully.
                </>
              )}
            </p>
            <p>You answered <span className="font-bold">{score} out of {questions.length}</span> questions correctly.</p>
          </div>
        </div>
      )}
    </div>
  )
}
