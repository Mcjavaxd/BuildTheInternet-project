import { FormEvent, useMemo, useState } from 'react';

type FlowNode = {
  id: number;
  icon: string;
  label: string;
  status: 'done' | 'active' | 'error' | 'pending';
  details?: string;
};

type ApiResponse = {
  status?: string;
  message?: string;
  error?: string;
  username?: string;
  user_id?: number;
  domain?: string;
  destination?: string;
  [key: string]: unknown;
};

const defaultDnsAddress = 'http://localhost:8000';
const userNotFoundPatterns = [
  'user not found',
  'user does not exist',
  'username not found',
  'no user',
  'not registered',
  'unknown user',
  'invalid username',
];

const normalizeHttpUrl = (value: string): string => {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }

  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  return withScheme.replace(/\/+$/, '');
};

const readJsonBody = async (response: Response): Promise<ApiResponse | null> => {
  const text = await response.text();
  if (!text) {
    return null;
  }

  try {
    return JSON.parse(text) as ApiResponse;
  } catch {
    return { error: text };
  }
};

const looksLikeUserNotFound = (payload: ApiResponse | null, status: number): boolean => {
  if (!payload) {
    return false;
  }

  const fields = [
    typeof payload.error === 'string' ? payload.error : '',
    typeof payload.message === 'string' ? payload.message : '',
    typeof payload.status === 'string' ? payload.status : '',
  ]
    .join(' ')
    .toLowerCase();

  if (status === 404) {
    return true;
  }

  return userNotFoundPatterns.some((pattern) => fields.includes(pattern));
};

const formatResponseError = (payload: ApiResponse | null, fallback: string): string => {
  if (payload?.error) {
    return String(payload.error);
  }
  if (payload?.message) {
    return String(payload.message);
  }
  return fallback;
};

function App() {
  const [dnsAddress, setDnsAddress] = useState(defaultDnsAddress);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [flow, setFlow] = useState<FlowNode[]>([
    { id: 1, icon: '👤', label: 'User', status: 'done' },
  ]);
  const [serverUrl, setServerUrl] = useState('');
  const [statusMessage, setStatusMessage] = useState('Ready for DNS resolution.');
  const [isLoading, setIsLoading] = useState(false);
  const [showAuth, setShowAuth] = useState(false);
  const [loginMessage, setLoginMessage] = useState('');

  const visibleFlow = useMemo(() => flow, [flow]);

  const appendFlow = (nodes: FlowNode[]) => {
    setFlow((current) => [...current, ...nodes]);
  };

  const resetFlow = (message: string) => {
    setFlow([
      { id: Date.now(), icon: '👤', label: 'User', status: 'done' },
    ]);
    setStatusMessage(message);
  };

  const startWorkflow = async () => {
    setIsLoading(true);
    setShowAuth(false);
    setLoginMessage('');
    setServerUrl('');
    setFlow([
      { id: 1, icon: '👤', label: 'User', status: 'done' },
      {
        id: 2,
        icon: '🌐',
        label: 'DNS Server',
        status: 'active',
        details: 'GET /lookup?domain=acm-server',
      },
    ]);
    setStatusMessage('Resolving acm-server through the DNS service...');

    try {
      const dnsUrl = normalizeHttpUrl(dnsAddress);
      if (!dnsUrl) {
        throw new Error('Enter a valid DNS server address.');
      }

      const response = await fetch(`${dnsUrl}/lookup?domain=acm-server`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
        },
      });

      const payload = await readJsonBody(response);
      if (!response.ok) {
        const message = formatResponseError(payload, 'DNS lookup failed.');
        throw new Error(message);
      }

      const destination = payload?.destination || payload?.address || payload?.host || payload?.url;
      if (!destination) {
        throw new Error('DNS response did not include a destination address.');
      }

      const resolvedServer = normalizeHttpUrl(String(destination));
      setServerUrl(resolvedServer);
      appendFlow([
        {
          id: Date.now() + 1,
          icon: '🖥️',
          label: 'acm-server',
          status: 'done',
          details: `Resolved at ${resolvedServer}`,
        },
      ]);
      setStatusMessage(`DNS lookup succeeded. ${resolvedServer} was resolved for acm-server.`);
      setShowAuth(true);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to resolve service address.';
      setStatusMessage(message);
      appendFlow([
        {
          id: Date.now() + 2,
          icon: '⚠️',
          label: 'DNS error',
          status: 'error',
          details: message,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const trimmedUsername = username.trim();
    const trimmedPassword = password.trim();

    if (!trimmedUsername || !trimmedPassword) {
      setLoginMessage('Username and password are required.');
      return;
    }

    if (!serverUrl) {
      setLoginMessage('Resolve the DNS entry before attempting login.');
      return;
    }

    setIsLoading(true);
    setLoginMessage('Authenticating user...');
    appendFlow([
      {
        id: Date.now() + 3,
        icon: '🔐',
        label: 'Login',
        status: 'active',
        details: 'POST /login',
      },
    ]);

    try {
      const response = await fetch(`${serverUrl}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          username: trimmedUsername,
          password: trimmedPassword,
        }),
      });

      const payload = await readJsonBody(response);

      if (response.ok) {
        appendFlow([
          { id: Date.now() + 4, icon: '🍪', label: 'Session Created', status: 'done' },
          { id: Date.now() + 5, icon: '🔎', label: 'GET /whoami', status: 'active' },
        ]);

        const whoamiResponse = await fetch(`${serverUrl}/whoami`, {
          method: 'GET',
          credentials: 'include',
          headers: {
            Accept: 'application/json',
          },
        });

        const whoamiPayload = await readJsonBody(whoamiResponse);

        if (!whoamiResponse.ok) {
          throw new Error(formatResponseError(whoamiPayload, 'Session verification failed.'));
        }

        appendFlow([
          {
            id: Date.now() + 6,
            icon: '✅',
            label: 'Session verified',
            status: 'done',
            details: whoamiPayload?.username ? `Authenticated as ${whoamiPayload.username}` : 'Authenticated user confirmed',
          },
        ]);

        setLoginMessage(`Welcome back, ${whoamiPayload?.username || trimmedUsername}.`);
        setStatusMessage('Session verified successfully.');
        return;
      }

      if (looksLikeUserNotFound(payload, response.status)) {
        appendFlow([
          { id: Date.now() + 7, icon: '🔐', label: 'User not found', status: 'error', details: 'Login failed: user does not exist' },
          { id: Date.now() + 8, icon: '📝', label: 'Register', status: 'active', details: 'POST /register' },
        ]);

        const registerResponse = await fetch(`${serverUrl}/register`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            username: trimmedUsername,
            password: trimmedPassword,
          }),
        });

        const registerPayload = await readJsonBody(registerResponse);
        if (!registerResponse.ok) {
          throw new Error(formatResponseError(registerPayload, 'Registration failed.'));
        }

        appendFlow([
          { id: Date.now() + 9, icon: '✅', label: 'Registration successful', status: 'done' },
          { id: Date.now() + 10, icon: '🔐', label: 'Retry Login', status: 'active', details: 'POST /login' },
        ]);

        const retryResponse = await fetch(`${serverUrl}/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            username: trimmedUsername,
            password: trimmedPassword,
          }),
        });

        const retryPayload = await readJsonBody(retryResponse);
        if (!retryResponse.ok) {
          throw new Error(formatResponseError(retryPayload, 'Retry login failed.'));
        }

        appendFlow([
          { id: Date.now() + 11, icon: '✅', label: 'Login successful', status: 'done' },
          { id: Date.now() + 12, icon: '🍪', label: 'Session Created', status: 'done' },
          { id: Date.now() + 13, icon: '🔎', label: 'GET /whoami', status: 'active' },
        ]);

        const finalWhoamiResponse = await fetch(`${serverUrl}/whoami`, {
          method: 'GET',
          credentials: 'include',
          headers: {
            Accept: 'application/json',
          },
        });

        const finalWhoamiPayload = await readJsonBody(finalWhoamiResponse);
        if (!finalWhoamiResponse.ok) {
          throw new Error(formatResponseError(finalWhoamiPayload, 'Session verification failed after registration.'));
        }

        appendFlow([
          {
            id: Date.now() + 14,
            icon: '✅',
            label: 'Session verified',
            status: 'done',
            details: finalWhoamiPayload?.username ? `Authenticated as ${finalWhoamiPayload.username}` : 'Authenticated user confirmed',
          },
        ]);

        setStatusMessage('Registration fallback completed and session verified.');
        setLoginMessage(`Welcome, ${finalWhoamiPayload?.username || trimmedUsername}.`);
        return;
      }

      throw new Error(formatResponseError(payload, 'Login failed.'));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Authentication failed.';
      setLoginMessage(message);
      setStatusMessage(message);
      appendFlow([
        {
          id: Date.now() + 15,
          icon: '⚠️',
          label: 'Authentication error',
          status: 'error',
          details: message,
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Build the Internet</p>
          <h1>acm-app</h1>
        </div>
        <div className="status-pill">
          <span className="status-pill-dot" />
          Online
        </div>
      </header>

      <main className="layout">
        <section className="panel hero-panel">
          <div className="hero-copy">
            <p className="eyebrow">Secure network access</p>
            <h2>Resolve services. Verify identity. Stay connected.</h2>
            <p>
              Discover the service endpoint, authenticate the user, and complete the request flow in one
              seamless sequence.
            </p>
          </div>

          <div className="hero-metrics">
            <div className="metric-card">
              <span className="metric-label">DNS</span>
              <strong>Lookup</strong>
            </div>
            <div className="metric-card">
              <span className="metric-label">Auth</span>
              <strong>Session</strong>
            </div>
            <div className="metric-card">
              <span className="metric-label">Flow</span>
              <strong>Live</strong>
            </div>
          </div>
        </section>

        <section className="panel controls-panel">
          <div className="field-group">
            <label htmlFor="dns-address">DNS Server Address</label>
            <input
              id="dns-address"
              type="url"
              value={dnsAddress}
              onChange={(event) => setDnsAddress(event.target.value)}
              placeholder="http://localhost:8000"
              disabled={isLoading}
            />
          </div>

          <button type="button" className="primary" onClick={startWorkflow} disabled={isLoading}>
            {isLoading ? 'Resolving...' : 'Start'}
          </button>
        </section>

        {showAuth && (
          <section className="panel auth-panel">
            <h2>Authentication</h2>
            <form onSubmit={handleLogin} className="auth-form">
              <div className="field-group">
                <label htmlFor="username">Username</label>
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={isLoading}
                  autoComplete="username"
                />
              </div>

              <div className="field-group">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={isLoading}
                  autoComplete="current-password"
                />
              </div>

              <button type="submit" className="primary" disabled={isLoading}>
                {isLoading ? 'Working...' : 'Login'}
              </button>
            </form>
          </section>
        )}

        <section className="panel flow-panel">
          <div className="status-row">
            <span className="status-dot" />
            <strong>{statusMessage}</strong>
          </div>

          <div className="flow-diagram" aria-live="polite">
            {visibleFlow.map((entry, index) => (
              <div key={entry.id} className="flow-step-wrap">
                {index > 0 && <div className="flow-connector" />}
                <div className={`flow-step ${entry.status}`}>
                  <span className="flow-icon">{entry.icon}</span>
                  <div className="flow-copy">
                    <span className="flow-label">{entry.label}</span>
                    {entry.details && <small>{entry.details}</small>}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {loginMessage && <div className="login-message">{loginMessage}</div>}
        </section>
      </main>
    </div>
  );
}

export default App;
