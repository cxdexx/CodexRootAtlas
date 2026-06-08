import { useMemo, useState } from 'react';

type TableInfo = {
  name: string;
  description: string;
  columns: Array<{ name: string; type: string; note?: string }>; 
};

type DemoState = {
  loginInput: string;
  searchInput: string;
  blindInput: string;
  timeInput: string;
};

type QuizQuestion = {
  id: string;
  question: string;
  options: string[];
  answer: string;
  explanation: string;
};

const schema: TableInfo[] = [
  {
    name: 'users',
    description: 'Accounts and login details for the app.',
    columns: [
      { name: 'id', type: 'INTEGER', note: 'PK' },
      { name: 'username', type: 'TEXT' },
      { name: 'password_hash', type: 'TEXT' },
      { name: 'role', type: 'TEXT' },
    ],
  },
  {
    name: 'products',
    description: 'Items available for search and purchase.',
    columns: [
      { name: 'id', type: 'INTEGER', note: 'PK' },
      { name: 'name', type: 'TEXT' },
      { name: 'category', type: 'TEXT' },
      { name: 'price', type: 'NUMERIC' },
    ],
  },
  {
    name: 'orders',
    description: 'Customer orders and shipment information.',
    columns: [
      { name: 'id', type: 'INTEGER', note: 'PK' },
      { name: 'user_id', type: 'INTEGER', note: 'FK → users.id' },
      { name: 'product_id', type: 'INTEGER', note: 'FK → products.id' },
      { name: 'status', type: 'TEXT' },
    ],
  },
];

const quizQuestions: QuizQuestion[] = [
  {
    id: 'quiz-1',
    question: 'Why is raw user input dangerous when inserted directly into SQL text?',
    options: [
      'It can change the query structure and let unexpected commands run.',
      'It makes the database slower by adding more text.',
      'It is only a problem for large databases.',
      'It causes server hardware to overheat.',
    ],
    answer: 'It can change the query structure and let unexpected commands run.',
    explanation: 'Unsafe input can change SQL logic, which is why parameterized queries are safer.',
  },
  {
    id: 'quiz-2',
    question: 'What does "least privilege" mean for a database account?',
    options: [
      'The account only has the permissions needed to do its job.',
      'The account can read and write every table.',
      'The account can install software on the database server.',
      'The account is shared with developers for convenience.',
    ],
    answer: 'The account only has the permissions needed to do its job.',
    explanation: 'Restricting permissions helps contain damage if the account is abused.',
  },
  {
    id: 'quiz-3',
    question: 'Which mitigation is the most reliable primary defense against SQLi?',
    options: [
      'Parameterized queries / prepared statements',
      'A web application firewall (WAF)',
      'Colorful error pages',
      'External monitoring only',
    ],
    answer: 'Parameterized queries / prepared statements',
    explanation: 'Prepared statements keep user input separate from SQL syntax and are the best first defense.',
  },
];

const demoProducts = [
  { id: 1, name: 'Blue widget' },
  { id: 2, name: 'Green gadget' },
  { id: 3, name: 'Red notebook' },
  { id: 4, name: 'Yellow tool kit' },
];

const App = () => {
  const [selectedTable, setSelectedTable] = useState(schema[0].name);
  const [flowMode, setFlowMode] = useState<'safe' | 'vulnerable'>('safe');
  const [demoMode, setDemoMode] = useState<'safe' | 'vulnerable'>('vulnerable');
  const [demoState, setDemoState] = useState<DemoState>({
    loginInput: "' OR '1'='1",
    searchInput: "widget' OR '1'='1",
    blindInput: "admin' OR '1'='1",
    timeInput: "sleep(5)",
  });
  const [openMitigation, setOpenMitigation] = useState<string>('prepared');
  const [quizAnswers, setQuizAnswers] = useState<Record<string, string>>({});
  const [quizFeedback, setQuizFeedback] = useState<Record<string, string>>({});

  const selectedSchema = schema.find((table) => table.name === selectedTable) ?? schema[0];

  const loginQuery = useMemo(() => {
    if (demoMode === 'vulnerable') {
      return `SELECT * FROM users WHERE username = '${demoState.loginInput}' AND password = 'password123';`;
    }
    return `PREPARE stmt FROM 'SELECT * FROM users WHERE username = ? AND password = ?';\nEXECUTE stmt USING '${demoState.loginInput}', 'password123';`;
  }, [demoMode, demoState.loginInput]);

  const searchQuery = useMemo(() => {
    if (demoMode === 'vulnerable') {
      return `SELECT * FROM products WHERE name LIKE '%${demoState.searchInput}%';`;
    }
    return `SELECT * FROM products WHERE name LIKE ?;\n-- parameter: '%${demoState.searchInput}%'`;
  }, [demoMode, demoState.searchInput]);

  const blindResult = useMemo(() => {
    if (demoMode === 'vulnerable' && demoState.blindInput.includes("' OR '1'='1")) {
      return 'Response: yes — condition matched, but no rows shown.';
    }
    return 'Response: no — query returned false, behavior is observed without data.';
  }, [demoMode, demoState.blindInput]);

  const timeResult = useMemo(() => {
    if (demoMode === 'vulnerable' && demoState.timeInput.toLowerCase().includes('sleep')) {
      return 'Simulated delay: 4.8s — query behaved as if a time-based condition was triggered.';
    }
    return 'Simulated response: fast result, no timing side effect detected.';
  }, [demoMode, demoState.timeInput]);

  const productResults = useMemo(() => {
    if (demoMode === 'vulnerable' && demoState.searchInput.includes("OR '1'='1")) {
      return demoProducts;
    }
    const query = demoState.searchInput.trim().toLowerCase();
    return demoProducts.filter((product) => product.name.toLowerCase().includes(query));
  }, [demoMode, demoState.searchInput]);

  const mitigationCards = [
    {
      key: 'prepared',
      title: 'Parameterized queries / prepared statements',
      summary: 'Separates data from command text so user input cannot change SQL structure.',
      details:
        'Use placeholders and bind values. This is the strongest primary defense against SQLi.',
      mistake: 'Treating escaping as enough instead of using real parameters.',
    },
    {
      key: 'validation',
      title: 'Input validation and sanitization',
      summary: 'Check inputs early and reject unexpected formats or lengths.',
      details: 'Ensure values match expected types and normalize input before use.',
      mistake: 'Relying on validation alone without parameterized execution.',
    },
    {
      key: 'least-privilege',
      title: 'Least privilege',
      summary: 'Give database accounts only the permissions needed.',
      details: 'Read-only apps should not use admin or owner accounts.',
      mistake: 'Using the same powerful account for all app operations.',
    },
    {
      key: 'errors',
      title: 'Safe error handling',
      summary: 'Hide internal database errors from users and log details securely.',
      details: 'Show friendly messages and keep stack details out of public pages.',
      mistake: 'Displaying raw SQL errors that reveal structure and schema details.',
    },
    {
      key: 'monitoring',
      title: 'Logging / monitoring',
      summary: 'Track suspicious input patterns and database failures over time.',
      details: 'Good logging helps detect attempts before they become a breach.',
      mistake: 'Logging nothing or storing sensitive secrets in plain text.',
    },
    {
      key: 'waf',
      title: 'WAF as secondary control',
      summary: 'Use a firewall to catch common attacks, but not instead of secure code.',
      details: 'WAFs help defense in depth, but code should still be safe by design.',
      mistake: 'Believing a WAF alone eliminates unsafe database handling.',
    },
  ];

  const handleQuizSubmit = (question: QuizQuestion, selection: string) => {
    const correct = selection === question.answer;
    setQuizAnswers((prev) => ({ ...prev, [question.id]: selection }));
    setQuizFeedback((prev) => ({
      ...prev,
      [question.id]: correct ? 'Correct! ' + question.explanation : 'Not quite. ' + question.explanation,
    }));
  };

  return (
    <div className="page-shell">
      <header className="site-header">
        <div className="branding">
          <div className="brand-mark">DB</div>
          <div>
            <h1 className="brand-title">SQL Injection Learning Lab</h1>
            <p className="brand-subtitle">Understand databases, safe queries, and SQLi prevention with guided visual demos.</p>
          </div>
        </div>
        <div className="nav-grid">
          <a className="nav-link" href="#intro">Intro</a>
          <a className="nav-link" href="#flow">App Flow</a>
          <a className="nav-link" href="#concept">SQLi Concept</a>
          <a className="nav-link" href="#demos">Simulators</a>
          <a className="nav-link" href="#mitigation">Mitigation</a>
          <a className="nav-link" href="#quiz">Quiz</a>
        </div>
      </header>

      <section className="section" id="intro">
        <div className="section-title">
          <span className="inline-badge">Step 1</span>
          What is a database?
        </div>
        <p className="section-description">
          A database stores structured information in tables. Each table has rows and columns, and the application uses SQL to ask for or update data.
        </p>

        <div className="diagram-grid">
          <div className="card table-card selected">
            <div className="table-heading">
              <div>
                <div className="table-name">Interactive schema</div>
                <p style={{ margin: 0, color: '#475569', fontSize: '0.95rem' }}>Click a table to explore columns and relationships.</p>
              </div>
            </div>
            <div className="button-group">
              {schema.map((table) => (
                <button
                  key={table.name}
                  className={`button secondary ${selectedTable === table.name ? 'active' : ''}`}
                  type="button"
                  onClick={() => setSelectedTable(table.name)}
                >
                  {table.name}
                </button>
              ))}
            </div>
            <ul className="column-list" style={{ marginTop: '1rem' }}>
              {selectedSchema.columns.map((column) => (
                <li key={column.name} className="column-item">
                  <span>{column.name}</span>
                  <span style={{ color: '#475569' }}> {column.type}{column.note ? ` • ${column.note}` : ''}</span>
                </li>
              ))}
            </ul>
            <p style={{ color: '#475569', marginTop: '1rem' }}>{selectedSchema.description}</p>
          </div>

          <div className="relationship-panel">
            <div className="diagram-box highlighted">
              <strong>Database tables</strong>
              <p style={{ margin: '0.7rem 0 0', color: '#334155' }}>
                Tables store data in rows and columns. The app uses schema definitions to understand what each column means.
              </p>
            </div>
            <div className="diagram-box">
              <strong>Primary key / foreign key</strong>
              <p style={{ margin: '0.7rem 0 0', color: '#334155' }}>
                Primary keys identify rows uniquely. Foreign keys link tables, such as <span className="inline-code">orders.user_id</span> → <span className="inline-code">users.id</span>.
              </p>
            </div>
            <div className="diagram-box">
              <strong>Schema</strong>
              <p style={{ margin: '0.7rem 0 0', color: '#334155' }}>
                A schema is the table layout and column types. It helps apps build valid queries and understand data structure.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="flow">
        <div className="section-title">
          <span className="inline-badge">Step 2</span>
          How the app talks to the database
        </div>
        <p className="section-description">
          See how user input moves from the page into a SQL query. Switch between safe and vulnerable flow to compare how the same input is handled differently.
        </p>

        <div className="card">
          <div className="button-group">
            <button type="button" className={`button secondary ${flowMode === 'safe' ? 'active' : ''}`} onClick={() => setFlowMode('safe')}>
              Safe mode
            </button>
            <button type="button" className={`button secondary ${flowMode === 'vulnerable' ? 'active' : ''}`} onClick={() => setFlowMode('vulnerable')}>
              Vulnerable mode
            </button>
          </div>

          <div className="flow-track" style={{ marginTop: '1.5rem' }}>
            <div className="flow-step">
              <div className="step-icon">1</div>
              <div>
                <strong>User input</strong>
                <p style={{ margin: '0.45rem 0 0', color: '#475569' }}>A user types a search term or login name into the app.</p>
              </div>
            </div>
            <div className="flow-step">
              <div className="step-icon">2</div>
              <div>
                <strong>Web app</strong>
                <p style={{ margin: '0.45rem 0 0', color: '#475569' }}>
                  The app takes that input and builds a SQL query. In safe mode, input stays separate from query structure.
                </p>
              </div>
            </div>
            <div className="flow-step">
              <div className="step-icon">3</div>
              <div>
                <strong>SQL query</strong>
                <p style={{ margin: '0.45rem 0 0', color: '#475569' }}>
                  {flowMode === 'safe'
                    ? 'Prepared statements keep the query text fixed and send user values separately.'
                    : 'Unsafe string concatenation mixes user text into the SQL command and can alter its meaning.'}
                </p>
              </div>
            </div>
            <div className="flow-step">
              <div className="step-icon">4</div>
              <div>
                <strong>Database</strong>
                <p style={{ margin: '0.45rem 0 0', color: '#475569' }}>The database evaluates the query and returns results or an error to the app.</p>
              </div>
            </div>
          </div>

          <div className="card-quiet" style={{ marginTop: '1.5rem' }}>
            <div className="section-title" style={{ alignItems: 'flex-start', gap: '0.6rem' }}>
              <span className="inline-badge">Query preview</span>
            </div>
            <div className="code-panel">
              <pre>
{flowMode === 'safe'
  ? `const sql = "SELECT * FROM products WHERE name LIKE ?";\nconst params = ["%userInput%"];
// userInput travels as data, not SQL code.`
  : `const sql = "SELECT * FROM products WHERE name LIKE '%" + userInput + "%'";
// userInput may change the query structure if it contains quotes.`}
              </pre>
            </div>
          </div>
        </div>
      </section>

      <section className="section" id="concept">
        <div className="section-title">
          <span className="inline-badge">Step 3</span>
          SQL injection explained
        </div>
        <p className="section-description">
          SQL injection happens when an application treats user input as part of the SQL command instead of plain data.
        </p>

        <div className="card-grid">
          <div className="card">
            <h3>Vulnerable example</h3>
            <div className="code-panel">
              <pre>
const sql = "SELECT * FROM users WHERE username = '" + userInput + "'";
const query = sql + " AND password = 'password123'";
              </pre>
            </div>
            <p style={{ marginTop: '1rem', color: '#475569' }}>
              If <span className="inline-code">userInput</span> contains SQL punctuation, the query changes shape and can bypass the intended check.
            </p>
          </div>
          <div className="card">
            <h3>Secure example</h3>
            <div className="code-panel">
              <pre>
const sql = "SELECT * FROM users WHERE username = ? AND password = ?";
const params = [userInput, 'password123'];
              </pre>
            </div>
            <p style={{ marginTop: '1rem', color: '#475569' }}>
              The query is fixed and the database treats <span className="inline-code">userInput</span> as a value, never as SQL commands.
            </p>
          </div>
        </div>
      </section>

      <section className="section" id="demos">
        <div className="section-title">
          <span className="inline-badge">Step 4</span>
          Safe simulator demos
        </div>
        <p className="section-description">
          These mock demos use pretend data only. They show how different SQLi ideas appear without running real exploits.
        </p>

        <div className="card">
          <div className="section-title" style={{ marginBottom: '0.5rem' }}>
            <span className="inline-badge">Login bypass</span>
            How a vulnerable login query can return too much if input is embedded directly.
          </div>
          <div className="input-row">
            <label>
              Username input
              <input
                className="input-field"
                value={demoState.loginInput}
                onChange={(event) => setDemoState({ ...demoState, loginInput: event.target.value })}
              />
            </label>
            <div className="button-group">
              <button type="button" className={`button secondary ${demoMode === 'vulnerable' ? 'active' : ''}`} onClick={() => setDemoMode('vulnerable')}>
                Vulnerable
              </button>
              <button type="button" className={`button secondary ${demoMode === 'safe' ? 'active' : ''}`} onClick={() => setDemoMode('safe')}>
                Secure
              </button>
            </div>
          </div>
          <div className="code-panel" style={{ marginTop: '1rem' }}>
            <pre>{loginQuery}</pre>
          </div>
          <div className="result-panel" style={{ marginTop: '1rem' }}>
            <p style={{ margin: 0 }}>
              {demoMode === 'vulnerable'
                ? 'Unsafe login code can allow input like "\' OR \'1\'=\'1" to make the query return a match even when the password is wrong.'
                : 'Safe prepared statements keep login input separate, so the query logic stays fixed and only valid credentials match.'}
            </p>
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.5rem' }}>
          <div className="section-title" style={{ marginBottom: '0.5rem' }}>
            <span className="inline-badge">Search query</span>
            See how product search input becomes part of a query.
          </div>
          <div className="input-row">
            <label>
              Search phrase
              <input
                className="input-field"
                value={demoState.searchInput}
                onChange={(event) => setDemoState({ ...demoState, searchInput: event.target.value })}
              />
            </label>
          </div>
          <div className="code-panel" style={{ marginTop: '1rem' }}>
            <pre>{searchQuery}</pre>
          </div>
          <div className="result-panel" style={{ marginTop: '1rem' }}>
            <p style={{ margin: 0, marginBottom: '0.75rem' }}>
              {demoMode === 'vulnerable'
                ? 'Unsafe search can return every product if input includes a classic injection payload.'
                : 'Secure search uses a placeholder and treats the phrase as data, so results are filtered correctly.'}
            </p>
            <div className="grid-3">
              {productResults.map((item) => (
                <div key={item.id} className="small-card">
                  {item.name}
                </div>
              ))}
              {productResults.length === 0 && <div className="small-card">No matching products</div>}
            </div>
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.5rem' }}>
          <div className="section-title" style={{ marginBottom: '0.5rem' }}>
            <span className="inline-badge">Blind SQLi</span>
            Conceptual feedback with yes/no behavior but no data output.
          </div>
          <div className="input-row">
            <label>
              Test input
              <input
                className="input-field"
                value={demoState.blindInput}
                onChange={(event) => setDemoState({ ...demoState, blindInput: event.target.value })}
              />
            </label>
          </div>
          <div className="result-panel" style={{ marginTop: '1rem' }}>
            <p style={{ margin: 0 }}>{blindResult}</p>
            <p style={{ margin: '0.75rem 0 0', color: '#475569' }}>
              In a blind SQLi scenario, an attacker learns if a condition is true without seeing actual rows.
            </p>
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.5rem' }}>
          <div className="section-title" style={{ marginBottom: '0.5rem' }}>
            <span className="inline-badge">Time-based SQLi</span>
            Conceptual delay detection without exposing database contents.
          </div>
          <div className="input-row">
            <label>
              Test input
              <input
                className="input-field"
                value={demoState.timeInput}
                onChange={(event) => setDemoState({ ...demoState, timeInput: event.target.value })}
              />
            </label>
          </div>
          <div className="result-panel" style={{ marginTop: '1rem' }}>
            <p style={{ margin: 0 }}>{timeResult}</p>
            <p style={{ margin: '0.75rem 0 0', color: '#475569' }}>
              A delayed response can reveal whether a hidden condition is true in the database.
            </p>
          </div>
        </div>

        <div className="card" style={{ marginTop: '1.5rem' }}>
          <div className="section-title" style={{ marginBottom: '0.5rem' }}>
            <span className="inline-badge">Out-of-band SQLi</span>
            When unsafe database behavior can trigger external communication.
          </div>
          <div className="diagram-box" style={{ display: 'grid', gap: '1rem' }}>
            <div>
              <strong>App</strong> receives user input, sends it to the database.
            </div>
            <div>
              <strong>Database</strong> can execute unsafe functions, then may reach external services.
            </div>
            <div>
              <strong>External listener</strong> receives outbound traffic, such as a DNS or HTTP callback.
            </div>
            <p style={{ margin: 0, color: '#475569' }}>
              Out-of-band SQLi is conceptual here: it shows that a database with too much privilege may leak data through external network calls.
            </p>
            <p style={{ margin: '0.75rem 0 0', color: '#475569' }}>
              Mitigations: restrict outbound access, disable dangerous functions, and use least privilege accounts.
            </p>
          </div>
        </div>
      </section>

      <section className="section" id="db-functions">
        <div className="section-title">
          <span className="inline-badge">Step 5</span>
          Database actions at a glance
        </div>
        <p className="section-description">
          SQL has basic commands for reading and changing data. These examples show what each command does in a friendly way.
        </p>

        <div className="grid-3">
          {[
            {
              title: 'SELECT',
              description: 'Read rows from a table.',
              example: "SELECT name FROM products WHERE category = 'tools';",
              note: 'Safe use means filtering with parameters, not string concatenation.',
            },
            {
              title: 'INSERT',
              description: 'Add a new row to a table.',
              example: "INSERT INTO users(username, password_hash) VALUES(?, ?);",
              note: 'Never insert raw user text into SQL without parameter binding.',
            },
            {
              title: 'UPDATE',
              description: 'Change existing rows based on a condition.',
              example: "UPDATE orders SET status = ? WHERE id = ?;",
              note: 'Use explicit WHERE clauses and parameters to avoid accidental data changes.',
            },
            {
              title: 'DELETE',
              description: 'Remove rows from a table safely.',
              example: "DELETE FROM orders WHERE id = ?;",
              note: 'Treat delete operations as sensitive and protect the input values.',
            },
          ].map((item) => (
            <div key={item.title} className="card">
              <h3 style={{ marginTop: 0 }}>{item.title}</h3>
              <p style={{ color: '#475569' }}>{item.description}</p>
              <div className="code-panel" style={{ marginTop: '1rem' }}>
                <pre>{item.example}</pre>
              </div>
              <p style={{ marginTop: '1rem', color: '#475569' }}>{item.note}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="section" id="mitigation">
        <div className="section-title">
          <span className="inline-badge">Step 6</span>
          Mitigation and safe database practices
        </div>
        <p className="section-description">
          Use multiple defensive controls. The strongest protection is secure query building plus sensible permissions and monitoring.
        </p>

        <div className="accordion">
          {mitigationCards.map((item) => (
            <div key={item.key} className="accordion-item">
              <button className="accordion-header" type="button" onClick={() => setOpenMitigation(item.key)}>
                {item.title}
                <span>{openMitigation === item.key ? '−' : '+'}</span>
              </button>
              {openMitigation === item.key && (
                <div className="accordion-content">
                  <p>{item.summary}</p>
                  <p><strong>Why it works:</strong> {item.details}</p>
                  <p><strong>Common mistake:</strong> {item.mistake}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="section" id="comparison">
        <div className="section-title">
          <span className="inline-badge">Step 7</span>
          Before vs after: vulnerable and secure flow
        </div>
        <p className="section-description">
          Compare the same application steps when the SQL query is built unsafely versus safely.
        </p>

        <div className="card-grid">
          <div className="card">
            <h3>Vulnerable flow</h3>
            <ul style={{ margin: 0, paddingLeft: '1.2rem', color: '#475569' }}>
              <li>User input is concatenated directly into SQL.</li>
              <li>The query text can change if the input contains quotes or operators.</li>
              <li>Unexpected results or data leaks may occur.</li>
            </ul>
          </div>
          <div className="card">
            <h3>Secure flow</h3>
            <ul style={{ margin: 0, paddingLeft: '1.2rem', color: '#475569' }}>
              <li>User input is sent separately from query syntax.</li>
              <li>The database receives a fixed statement and safe values.</li>
              <li>Only intended rows are returned.</li>
            </ul>
          </div>
        </div>
      </section>

      <section className="section" id="quiz">
        <div className="section-title">
          <span className="inline-badge">Step 8</span>
          Knowledge checks
        </div>
        <p className="section-description">
          Try these short questions to test what you learned. Each answer includes a quick explanation.
        </p>

        <div className="quiz-card">
          {quizQuestions.map((question) => (
            <div key={question.id} className="card">
              <h4>{question.question}</h4>
              <div className="quiz-options">
                {question.options.map((option) => (
                  <label key={option} className="quiz-option">
                    <input
                      type="radio"
                      name={question.id}
                      value={option}
                      checked={quizAnswers[question.id] === option}
                      onChange={() => handleQuizSubmit(question, option)}
                    />
                    {option}
                  </label>
                ))}
              </div>
              {quizFeedback[question.id] && (
                <div className="quiz-feedback">
                  {quizFeedback[question.id]}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <footer className="footer">
        <p>Safe learning lab created for conceptual understanding of SQL and SQL injection prevention.</p>
      </footer>
    </div>
  );
};

export default App;
