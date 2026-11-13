import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { Link, NavLink, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import { Activity, AlertTriangle, ArrowDownToLine, ArrowUpRight, BarChart3, Check, ChevronRight, CircleHelp, Clock3, FileSearch, FileUp, Fingerprint, LayoutDashboard, LoaderCircle, LockKeyhole, LogOut, Menu, Network, Search, Shield, ShieldCheck, Siren, UserRoundCog, Users, X } from 'lucide-react'
import { api, downloadFile, query, saveDownload, token, uploadFile } from './api'

const cx = (...parts) => parts.filter(Boolean).join(' ')
const fmtDate = value => value ? new Date(value).toLocaleString() : '—'

function useDebouncedValue(value, delay = 250) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  return debounced
}

function App() {
  const [user, setUser] = useState(null)
  const [checking, setChecking] = useState(Boolean(token()))
  const [authError, setAuthError] = useState('')
  const location = useLocation()
  const navigate = useNavigate()

  const loadUser = useCallback(async () => {
    if (!token()) { setChecking(false); setUser(null); return }
    try { const current = await api('/auth/me'); setUser(current); setAuthError(''); return current }
    catch (error) { setUser(null); throw error }
    finally { setChecking(false) }
  }, [])

  useEffect(() => {
    loadUser().catch(() => {})
    const expired = () => { setUser(null); setAuthError('Your session expired or was revoked. Sign in again.'); navigate('/login') }
    window.addEventListener('session-expired', expired)
    return () => window.removeEventListener('session-expired', expired)
  }, [loadUser, navigate])

  async function signIn(credentials) {
    setAuthError('')
    try {
      const result = await api('/auth/login', { method: 'POST', body: JSON.stringify(credentials) })
      localStorage.setItem('access_token', result.access_token)
      const current = await loadUser()
      if (!current) throw new Error('Unable to verify your account. Sign in again.')
      navigate('/')
    } catch (error) { localStorage.removeItem('access_token'); setUser(null); setAuthError(error.message) }
  }

  async function signOut() {
    let logoutError = ''
    try { await api('/auth/logout', { method: 'POST' }) } catch (error) { if (error.status !== 401) logoutError = 'Signed out on this device, but the server could not confirm token revocation.' }
    localStorage.removeItem('access_token')
    setUser(null)
    setAuthError(logoutError)
    navigate('/login')
  }

  if (checking) return <div className="center-page"><LoaderCircle className="spin" size={24} /> Verifying session…</div>
  if (!user) return <Routes><Route path="*" element={<Login onSubmit={signIn} error={authError} />} /></Routes>

  const admin = user.role === 'administrator'
  return <div className="app-shell">
    <Sidebar user={user} admin={admin} onSignOut={signOut} />
    <main className="main-area">
      <header className="topbar">
        <div className="mobile-brand"><Shield size={18} /><span>SENTINEL</span></div>
        <div className="crumb"><span>Workspace</span><ChevronRight size={14} /><b>{pageTitle(location.pathname)}</b></div>
        <div className="top-actions"><span className="live-indicator"><i /> Authenticated</span><span className="avatar">{user.username.slice(0, 1).toUpperCase()}</span><span className="top-user">{user.username}</span></div>
      </header>
      <div className="content-wrap">
        <Routes>
          <Route path="/" element={<Dashboard admin={admin} />} />
          <Route path="/analyses" element={<Analyses />} />
          <Route path="/analyses/:id" element={<AnalysisDetail />} />
          <Route path="/alerts" element={<Alerts admin={admin} />} />
          <Route path="/alerts/:id" element={<AlertDetail admin={admin} />} />
          {admin && <Route path="/users" element={<UsersPage currentUser={user} />} />}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </div>
    </main>
  </div>
}

function pageTitle(path) {
  if (path.startsWith('/analyses/')) return 'Analysis details'
  if (path === '/analyses') return 'Analyses'
  if (path.startsWith('/alerts/')) return 'Alert details'
  if (path === '/alerts') return 'Alerts'
  if (path === '/users') return 'User management'
  return 'Overview'
}

function Sidebar({ user, admin, onSignOut }) {
  const [open, setOpen] = useState(false)
  const links = [
    { to: '/', label: 'Overview', icon: LayoutDashboard },
    { to: '/analyses', label: 'Analysis jobs', icon: FileSearch },
    { to: '/alerts', label: 'Threat alerts', icon: Siren },
    ...(admin ? [{ to: '/users', label: 'User management', icon: Users }] : []),
  ]
  return <>
    <button className="mobile-menu" onClick={() => setOpen(!open)} aria-label="Toggle navigation" aria-expanded={open} aria-controls="primary-navigation">{open ? <X /> : <Menu />}</button>
    {open && <button className="mobile-scrim" onClick={() => setOpen(false)} aria-label="Close navigation" />}
    <aside className={cx('sidebar', open && 'sidebar-open')}>
      <Link to="/" className="brand"><span className="brand-mark"><Shield size={20} /></span><span><b>SENTINEL</b><small>NETWORK DEFENSE</small></span></Link>
      <div className="workspace-tag"><span className="workspace-dot" /> LOCAL ENVIRONMENT <span className="chevron">⌄</span></div>
      <div className="nav-caption">OPERATIONS</div>
      <nav id="primary-navigation">{links.map(({ to, label, icon: Icon }) => <NavLink key={to} end={to === '/'} to={to} className={({ isActive }) => cx('nav-link', isActive && 'nav-active')} onClick={() => setOpen(false)}><Icon size={17} /><span>{label}</span>{to === '/alerts' && <span className="nav-arrow">↗</span>}</NavLink>)}</nav>
      <div className="sidebar-bottom">
        <div className="posture"><div className="posture-icon"><ShieldCheck size={18} /></div><div><b>Defense posture</b><span>Monitoring enabled</span></div><i /></div>
        <div className="profile"><div className="avatar">{user.username.slice(0, 1).toUpperCase()}</div><div className="profile-copy"><b>{user.username}</b><span>{admin ? 'Administrator' : 'Normal User'}</span></div><button className="icon-button" onClick={onSignOut} title="Sign out" aria-label="Sign out"><LogOut size={16} /></button></div>
      </div>
    </aside>
  </>
}

function Login({ onSubmit, error }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(event) { event.preventDefault(); setBusy(true); await onSubmit({ username, password }); setBusy(false) }
  return <div className="login-page"><div className="login-side"><div className="login-grid" /><div className="login-copy"><span className="eyebrow"><i /> SECURITY OPERATIONS CENTER</span><h1>See the signals.<br /><em>Stop the threats.</em></h1><p>Analyze network captures, investigate explainable detections, and keep every finding in view.</p><div className="login-proof"><span><Fingerprint size={16} /> Role-scoped access</span><span><Activity size={16} /> PCAP analysis</span><span><ShieldCheck size={16} /> Auditable findings</span></div><div className="login-decoration"><Network size={210} strokeWidth={0.7} /></div></div><div className="login-foot">SENTINEL <span>·</span> DEFENSIVE NETWORK ANALYSIS</div></div><div className="login-form-side"><div className="login-form-wrap"><div className="login-mobile-logo"><Shield size={19} /> SENTINEL</div><span className="eyebrow muted">WELCOME BACK</span><h2>Sign in to Sentinel</h2><p className="muted-text">Use your project account to access the workspace.</p><form onSubmit={submit} className="form-stack"><label>Username<input autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} placeholder="Enter your username" /></label><label>Password<input autoComplete="current-password" type="password" required value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter your password" /></label>{error && <div className="alert-error" role="alert"><AlertTriangle size={16} />{error}</div>}<button className="button primary full" disabled={busy}>{busy ? <><LoaderCircle className="spin" size={16} /> Signing in…</> : <>Continue <ArrowUpRight size={16} /></>}</button></form><div className="login-safe"><LockKeyhole size={14} /> Protected by role-based access control</div></div><div className="login-footer">For authorized defensive analysis only.</div></div></div>
}

function PageHeading({ eyebrow = 'SECURITY OPERATIONS', title, description, action }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div>
}

function Dashboard({ admin }) {
  const [data, setData] = useState(null)
  const [jobs, setJobs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const requestId = useRef(0)
  const [filter, setFilter] = useState({ severity: '', method: '', since: '', until: '' })
  const params = query(filter)
  const load = useCallback(async ({ quiet = false } = {}) => {
    const currentRequest = ++requestId.current
    if (!quiet) setLoading(true)
    try {
      const [summary, jobRows, alertRows] = await Promise.all([api(`/dashboard${params}`), api('/analyses?limit=5'), api(`/alerts?limit=5${params ? `&${params.slice(1)}` : ''}`)])
      if (currentRequest === requestId.current) { setData(summary); setJobs(jobRows); setAlerts(alertRows); setError('') }
    } catch (e) { if (currentRequest === requestId.current) setError(e.message) } finally { if (currentRequest === requestId.current) setLoading(false) }
  }, [params])
  useEffect(() => { load(); const timer = setInterval(() => load({ quiet: true }), 15000); return () => clearInterval(timer) }, [load])
  const totalSignals = data?.alert_count ?? 0
  return <>
    <PageHeading eyebrow={admin ? 'ADMINISTRATOR CONSOLE' : 'PERSONAL WORKSPACE'} title={admin ? 'Security overview' : 'Your analysis overview'} description={admin ? 'A live view of analysis activity and detected threats across the workspace.' : 'A clear picture of your captures, analysis jobs, and detected signals.'} action={<button className="button secondary" onClick={load}><Activity size={16} /> Refresh data</button>} />
    {error && <ErrorBanner message={error} onRetry={load} />}
    <div className="filter-row"><div className="filter-label"><BarChart3 size={15} /> FILTER VIEW</div><label>Severity<select value={filter.severity} onChange={e => setFilter({ ...filter, severity: e.target.value })}><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label><label>Detection type<select value={filter.method} onChange={e => setFilter({ ...filter, method: e.target.value })}><option value="">All methods</option><option value="signature">Signature</option><option value="model">Model</option></select></label><label>From<input type="datetime-local" value={filter.since} onChange={e => setFilter({ ...filter, since: e.target.value ? new Date(e.target.value).toISOString() : '' })} /></label><label>To<input type="datetime-local" value={filter.until} onChange={e => setFilter({ ...filter, until: e.target.value ? new Date(e.target.value).toISOString() : '' })} /></label></div>
    <div className="stat-grid">
      <StatCard icon={FileSearch} label="ANALYSIS JOBS" value={loading || !data ? '—' : data.analysis_count} hint="Stored in your workspace" tone="blue" />
      <StatCard icon={Siren} label="DETECTION ALERTS" value={loading || !data ? '—' : totalSignals} hint={data?.alerts_by_severity?.high ? `${data.alerts_by_severity.high} high severity` : data ? 'No high severity alerts' : 'Unavailable'} tone="red" />
      <StatCard icon={Activity} label="COMPLETED JOBS" value={loading || !data ? '—' : data.jobs_by_status?.completed ?? 0} hint={data ? `${data.jobs_by_status?.running || 0} currently running` : 'Unavailable'} tone="mint" />
      <StatCard icon={ShieldCheck} label="OPEN ALERTS" value={loading || !data ? '—' : data.alerts_by_status?.open ?? 0} hint={data ? 'Requires review' : 'Unavailable'} tone="amber" />
    </div>
    <div className="dashboard-groups"><div className="group-strip"><b>Analysis status</b><div>{['queued', 'running', 'completed', 'failed'].map(status => <span className="group-chip" key={status}>{status} <strong>{data ? data.jobs_by_status?.[status] ?? 0 : '—'}</strong></span>)}</div></div><div className="group-strip"><b>Alert severity</b><div>{['critical', 'high', 'medium', 'low'].map(severity => <span className={`group-chip severity-${severity}`} key={severity}>{severity} <strong>{data ? data.alerts_by_severity?.[severity] ?? 0 : '—'}</strong></span>)}</div></div></div>
    <div className="dashboard-columns">
      <section className="panel"><div className="panel-heading"><div><span className="panel-kicker">RECENT ACTIVITY</span><h2>Analysis jobs</h2></div><Link to="/analyses" className="text-link">View all <ArrowUpRight size={14} /></Link></div><JobTable jobs={jobs} loading={loading} unavailable={Boolean(error) && jobs.length === 0} compact /></section>
      <section className="panel"><div className="panel-heading"><div><span className="panel-kicker">DETECTION FEED</span><h2>Recent alerts</h2></div><Link to="/alerts" className="text-link">View all <ArrowUpRight size={14} /></Link></div><AlertList alerts={alerts.slice(0, 4)} loading={loading} unavailable={Boolean(error) && alerts.length === 0} /></section>
    </div>
    <div className="dashboard-footnote"><CircleHelp size={14} /> Metrics are computed from stored analysis jobs and alerts. Detection labels represent the configured analysis method.</div>
  </>
}

function StatCard({ icon: Icon, label, value, hint, tone }) {
  return <div className="stat-card"><div className="stat-top"><span>{label}</span><div className={`stat-icon ${tone}`}><Icon size={17} /></div></div><strong>{value}</strong><small>{hint}</small><div className={`stat-accent ${tone}`} /></div>
}

function Analyses() {
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filters, setFilters] = useState({ status: '', q: '', skip: 0 })
  const [refresh, setRefresh] = useState(0)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [uploadError, setUploadError] = useState('')
  const [notice, setNotice] = useState('')
  const uploadLock = useRef(false)
  const requestId = useRef(0)
  const debouncedSearch = useDebouncedValue(filters.q)
  const search = query({ status: filters.status, q: debouncedSearch, skip: filters.skip, limit: 20 })
  useEffect(() => { let alive = true; const currentRequest = ++requestId.current; setLoading(true); setError(''); api(`/analyses${search}`).then(rows => { if (alive && currentRequest === requestId.current) setJobs(rows) }).catch(e => { if (alive && currentRequest === requestId.current) setError(e.message) }).finally(() => { if (alive && currentRequest === requestId.current) setLoading(false) }); return () => { alive = false } }, [search, refresh])
  useEffect(() => {
    if (!jobs.some(job => ['queued', 'running'].includes(job.status))) return
    const timer = setInterval(() => {
      const currentRequest = ++requestId.current
      api(`/analyses${search}`).then(rows => { if (currentRequest === requestId.current) { setJobs(rows); setError('') } }).catch(e => { if (currentRequest === requestId.current) setError(e.message) }).finally(() => { if (currentRequest === requestId.current) setLoading(false) })
    }, 4000)
    return () => clearInterval(timer)
  }, [jobs, search])
  async function upload(file) {
    if (uploadLock.current) return
    setUploadError(''); setNotice('')
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.pcap') && !file.name.toLowerCase().endsWith('.pcapng')) {
      setUploadError('Choose a .pcap or .pcapng capture.')
      return
    }
    uploadLock.current = true
    setUploading(true)
    setUploadProgress(0)
    const form = new FormData(); form.append('file', file)
    try { const result = await uploadFile('/analyses', form, setUploadProgress); setNotice(`Capture accepted · job ${result.id.slice(-8)} queued for analysis.`); setFilters(previous => ({ ...previous, status: '', skip: 0 })); setRefresh(n => n + 1) }
    catch (e) { setUploadError(e.message) } finally { uploadLock.current = false; setUploading(false) }
  }
  return <>
    <PageHeading title="Analysis jobs" description="Upload authorized PCAP or PCAPNG captures and follow their processing results." action={<button className="button secondary" onClick={() => setRefresh(n => n + 1)}><Activity size={16} /> Refresh</button>} />
    <UploadPanel onUpload={upload} busy={uploading} progress={uploadProgress} error={uploadError} notice={notice} />
    {error && <ErrorBanner message={error} onRetry={() => setRefresh(n => n + 1)} />}
    <section className="panel table-panel"><div className="panel-heading table-toolbar"><div><span className="panel-kicker">CAPTURE HISTORY</span><h2>All analysis jobs</h2></div><div className="toolbar-controls"><div className="search-box"><Search size={15} /><input aria-label="Search analysis filenames" placeholder="Search filename…" value={filters.q} onChange={e => setFilters({ ...filters, q: e.target.value, skip: 0 })} /></div><select aria-label="Filter analyses by status" value={filters.status} onChange={e => setFilters({ ...filters, status: e.target.value, skip: 0 })}><option value="">All statuses</option>{['queued', 'running', 'completed', 'failed'].map(s => <option key={s} value={s}>{s}</option>)}</select></div></div>{error && !loading ? <div className="table-state">Could not load analysis jobs. Retry after checking the connection.</div> : <JobTable jobs={jobs} loading={loading} />}<div className="pagination"><span>Showing {jobs.length} job{jobs.length === 1 ? '' : 's'}</span><div><button disabled={filters.skip === 0} onClick={() => setFilters({ ...filters, skip: Math.max(0, filters.skip - 20) })}>Previous</button><button disabled={jobs.length < 20} onClick={() => setFilters({ ...filters, skip: filters.skip + 20 })}>Next</button></div></div></section>
  </>
}

function UploadPanel({ onUpload, busy, progress, error, notice }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile] = useState(null)
  const input = useId()
  function choose(f) { if (!busy) { setFile(f || null); if (f) onUpload(f) } }
  return <section className={cx('upload-panel', dragging && 'dragging')} onDragOver={e => { e.preventDefault(); if (!busy) setDragging(true) }} onDragLeave={() => setDragging(false)} onDrop={e => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files?.[0]) }}>
    <div className="upload-icon"><FileUp size={20} /></div><div className="upload-copy"><b>{busy ? `Uploading capture… ${progress}%` : file ? file.name : 'Drop a capture to begin analysis'}</b><span>PCAP and PCAPNG · maximum size is enforced by the API</span>{busy && <progress className="upload-progress" max="100" value={progress} aria-label="Upload progress" />}{error && <span className="inline-error" role="alert">{error}</span>}{notice && <span className="inline-success" role="status"><Check size={13} />{notice}</span>}</div><label className="button primary upload-button" htmlFor={input}>{busy ? <><LoaderCircle size={15} className="spin" /> Uploading</> : 'Choose capture'}<input id={input} type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng" disabled={busy} onChange={e => { choose(e.target.files?.[0]); e.target.value = '' }} /></label>
  </section>
}

function JobTable({ jobs, loading, unavailable = false, compact = false }) {
  if (loading) return <div className="table-state"><LoaderCircle className="spin" size={18} /> Loading analysis jobs…</div>
  if (unavailable) return <div className="table-state">Analysis jobs are unavailable. Retry after checking the connection.</div>
  if (!jobs.length) return <EmptyState icon={FileSearch} title="No analysis jobs yet" description="Upload an authorized capture above to create your first job." />
  return <div className="table-scroll"><table><thead><tr><th>CAPTURE</th><th>STATUS</th><th>PACKETS</th><th>ALERTS</th><th>SUBMITTED</th><th></th></tr></thead><tbody>{jobs.map(job => <tr key={job.id}><td><Link className="file-cell" to={`/analyses/${job.id}`}><span className="file-icon"><Network size={15} /></span><span><b>{job.filename}</b><small>{(job.file_size / 1024).toFixed(1)} KB · {job.id.slice(-8)}</small></span></Link></td><td><StatusPill status={job.status} /></td><td>{job.summary?.packet_count ?? '—'}</td><td>{job.summary?.alert_count ?? '—'}</td><td>{fmtDate(job.created_at)}</td><td><Link className="row-link" to={`/analyses/${job.id}`} aria-label="View analysis"><ChevronRight size={17} /></Link></td></tr>)}</tbody></table></div>
}

function AnalysisDetail() {
  const { id } = useParams()
  const [job, setJob] = useState(null)
  const jobRef = useRef(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [refreshError, setRefreshError] = useState('')
  const [findingsError, setFindingsError] = useState('')
  const [exportError, setExportError] = useState('')
  const [exporting, setExporting] = useState(false)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const load = useCallback(async ({ quiet = false } = {}) => { if (!quiet) setLoading(true); try { const current = await api(`/analyses/${id}`); jobRef.current = current; setJob(current); setError(''); setRefreshError('') } catch (e) { if (quiet && jobRef.current) setRefreshError(e.message); else setError(e.message) } finally { setLoading(false) } }, [id])
  async function exportAnalysis() {
    setExporting(true); setExportError('')
    try { const file = await downloadFile(`/analyses/${id}/export`, `analysis-${id}.csv`); saveDownload(file.blob, file.filename) }
    catch (e) { setExportError(e.message) } finally { setExporting(false) }
  }
  async function loadMoreFindings() {
    if (!job || findingsLoading) return
    const summary = job.summary || {}
    const current = summary.findings || []
    setFindingsLoading(true); setFindingsError('')
    try {
      const page = await api(`/analyses/${id}/findings?skip=${current.length}&limit=50`)
      setJob(previous => ({
        ...previous,
        summary: {
          ...previous.summary,
          findings: [...(previous.summary?.findings || []), ...page.items],
          findings_pagination: { skip: page.skip, limit: page.limit, total: page.total, has_more: page.has_more },
        },
      }))
    } catch (e) { setFindingsError(e.message) } finally { setFindingsLoading(false) }
  }
  useEffect(() => { jobRef.current = null; setJob(null); setError(''); setLoading(true); load() }, [id, load])
  useEffect(() => { if (!job || !['queued', 'running'].includes(job.status)) return; const timer = setInterval(() => load({ quiet: true }), 2500); return () => clearInterval(timer) }, [job?.status, load])
  if (loading) return <LoadingPage />
  if (error) return <ErrorBanner message={error} onRetry={load} />
  const summary = job.summary || {}
  const mlScoring = summary.ml_scoring || { status: 'skipped', reason: 'No model status was recorded.' }
  return <>
    <PageHeading eyebrow="ANALYSIS JOB" title={job.filename} description={`Submitted ${fmtDate(job.created_at)} · job ${job.id}`} action={<><Link className="button secondary" to="/analyses">Back to jobs</Link><button className="button secondary" onClick={exportAnalysis} disabled={exporting}><ArrowDownToLine size={15} /> {exporting ? 'Preparing export…' : 'Export summary'}</button></>} />
    <div className="detail-status"><div><span className="panel-kicker">JOB STATUS</span><div className="detail-state" aria-live="polite"><StatusPill status={job.status} />{job.status === 'queued' && <span className="muted-text">Waiting for a processing worker. This view refreshes automatically.</span>}{job.status === 'running' && <span className="muted-text">A worker is processing or recovering this capture. This view refreshes automatically.</span>}</div></div><div className="detail-times"><span><Clock3 size={14} /> Started {fmtDate(job.started_at)}</span><span><Check size={14} /> Finished {fmtDate(job.finished_at)}</span></div></div>
    {job.error_message && <ErrorBanner message={job.error_message} />}
    {exportError && <ErrorBanner message={exportError} onRetry={exportAnalysis} />}
    {refreshError && <ErrorBanner message={`Live status refresh failed: ${refreshError}`} onRetry={() => load({ quiet: true })} />}
    {job.status === 'completed' && <><div className="stat-grid detail-stats"><StatCard icon={Network} label="PACKETS PARSED" value={summary.packet_count ?? 0} hint={summary.source_format?.toUpperCase() || 'Capture'} tone="blue" /><StatCard icon={Activity} label="FLOWS DERIVED" value={summary.flow_count ?? 0} hint="Endpoint and protocol groups" tone="mint" /><StatCard icon={Siren} label="DETECTION ALERTS" value={summary.alert_count ?? 0} hint="Persisted for this job" tone="red" /><StatCard icon={Fingerprint} label="DETECTION METHOD" value={summary.detection === 'signature_rules' ? 'Signatures' : summary.detection || '—'} hint="Explainable rule catalog" tone="amber" /></div><div className="panel result-panel"><div className="panel-heading"><div><span className="panel-kicker">DETECTION RESULTS</span><h2>Findings</h2></div><span className="method-tag"><Fingerprint size={14} /> SIGNATURE ANALYSIS</span></div>{findingsError && <ErrorBanner message={findingsError} onRetry={loadMoreFindings} />}{(summary.findings || []).length ? <div className="finding-list">{summary.findings.map((f, index) => <div className="finding" key={`${f.rule_id}-${f.title}-${index}`}><div className="finding-mark"><AlertTriangle size={17} /></div><div className="finding-copy"><div className="finding-top"><b>{f.title}</b><SeverityPill severity={f.severity} /></div><p>{f.description}</p><div className="evidence-grid"><span>Rule <b>{f.rule_id} · v{f.rule_version}</b></span>{Object.entries(f.evidence || {}).map(([key, value]) => <span key={key}>{key.replaceAll('_', ' ')} <b>{Array.isArray(value) ? value.join(', ') : String(value)}</b></span>)}</div>{f.indicator_context?.length > 0 && <div className="indicator-note"><ShieldCheck size={13} /> Matched local indicator data: {f.indicator_context.map(item => `${item.indicator} (${item.source})`).join(', ')}</div>}</div></div>)}</div> : <EmptyState icon={ShieldCheck} title="No matching signatures" description="No enabled signature rule matched this capture. This is not a guarantee that traffic is benign." />}<div className="pagination"><span>Showing {Math.min(summary.findings?.length || 0, summary.findings_pagination?.total || 0)} of {summary.findings_pagination?.total || 0} findings</span>{summary.findings_pagination?.has_more && <button className="button secondary" disabled={findingsLoading} onClick={loadMoreFindings}>{findingsLoading ? 'Loading…' : 'Load more findings'}</button>}</div></div><div className="ml-note"><CircleHelp size={15} /><span><b>ML scoring: {mlScoring.status}.</b> {mlScoring.reason || 'No approved model artifact is configured.'} Signature results remain distinct from model scoring.</span></div></>}
  </>
}

function Alerts({ admin }) {
  const [alerts, setAlerts] = useState([])
  const [filters, setFilters] = useState({ severity: '', method: '', status: '', q: '', skip: 0 })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')
  const requestId = useRef(0)
  const debouncedAlertQuery = useDebouncedValue(filters.q)
  const search = query({ ...filters, q: debouncedAlertQuery, limit: 25 })
  const exportSearch = query({ severity: filters.severity, method: filters.method, status: filters.status, q: debouncedAlertQuery })
  const load = useCallback(() => { const currentRequest = ++requestId.current; setLoading(true); setError(''); api(`/alerts${search}`).then(rows => { if (currentRequest === requestId.current) setAlerts(rows) }).catch(e => { if (currentRequest === requestId.current) setError(e.message) }).finally(() => { if (currentRequest === requestId.current) setLoading(false) }) }, [search])
  async function exportAlerts() {
    setExporting(true); setExportError('')
    try { const file = await downloadFile(`/alerts/export${exportSearch}`, 'alerts.csv'); saveDownload(file.blob, file.filename) }
    catch (e) { setExportError(e.message) } finally { setExporting(false) }
  }
  useEffect(() => { load() }, [load])
  return <>
    <PageHeading title="Threat alerts" description="Investigate explainable findings linked to your analysis jobs." action={<><button className="button secondary" onClick={exportAlerts} disabled={exporting}><ArrowDownToLine size={15} /> {exporting ? 'Preparing…' : 'Export CSV'}</button><button className="button secondary" onClick={load}><Activity size={16} /> Refresh</button></>} />
    <div className="filter-row alert-filters"><div className="filter-label"><Search size={15} /> FILTER ALERTS</div><div className="search-box"><Search size={15} /><input aria-label="Search alert title or category" placeholder="Search title or category…" value={filters.q} onChange={e => setFilters({ ...filters, q: e.target.value, skip: 0 })} /></div><select aria-label="Filter alerts by severity" value={filters.severity} onChange={e => setFilters({ ...filters, severity: e.target.value, skip: 0 })}><option value="">All severities</option>{['critical', 'high', 'medium', 'low'].map(s => <option key={s}>{s}</option>)}</select><select aria-label="Filter alerts by detection method" value={filters.method} onChange={e => setFilters({ ...filters, method: e.target.value, skip: 0 })}><option value="">All methods</option><option value="signature">Signature</option><option value="model">Model</option></select><select aria-label="Filter alerts by workflow status" value={filters.status} onChange={e => setFilters({ ...filters, status: e.target.value, skip: 0 })}><option value="">All states</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select></div>
    {error && <ErrorBanner message={error} onRetry={load} />}{exportError && <ErrorBanner message={exportError} onRetry={exportAlerts} />}
    <section className="panel table-panel"><div className="panel-heading"><div><span className="panel-kicker">DETECTION REVIEW</span><h2>{alerts.length} alert{alerts.length === 1 ? '' : 's'} on this page</h2></div>{admin && <span className="admin-view"><ShieldCheck size={14} /> ALL USERS</span>}</div>{loading ? <div className="table-state"><LoaderCircle className="spin" size={18} /> Loading alerts…</div> : alerts.length ? <div className="alert-table">{alerts.map(alert => <Link to={`/alerts/${alert.id}`} className="alert-row" key={alert.id}><div className="alert-severity"><SeverityPill severity={alert.severity} /></div><div className="alert-row-copy"><b>{alert.title}</b><span>{alert.category} <i>·</i> {alert.method} <i>·</i> job {alert.job_id.slice(-8)}</span></div><StatusPill status={alert.status} /><time>{fmtDate(alert.occurred_at)}</time><ChevronRight size={17} /></Link>)}</div> : error ? <div className="table-state">Alerts could not be loaded. Retry after checking the connection.</div> : <EmptyState icon={ShieldCheck} title="No alerts match this view" description="New findings will appear here when an analysis rule matches the submitted capture." />}<div className="pagination"><span>Showing {alerts.length ? filters.skip + 1 : 0}–{filters.skip + alerts.length}</span><div><button disabled={filters.skip === 0} onClick={() => setFilters({ ...filters, skip: Math.max(0, filters.skip - 25) })}>Previous</button><button disabled={alerts.length < 25} onClick={() => setFilters({ ...filters, skip: filters.skip + 25 })}>Next</button></div></div></section>
  </>
}

function AlertDetail({ admin }) {
  const { id } = useParams()
  const [alert, setAlert] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const load = useCallback(async () => { try { setAlert(await api(`/alerts/${id}`)); setError('') } catch (e) { setError(e.message) } }, [id])
  useEffect(() => { load() }, [load])
  async function updateStatus(status) { setBusy(true); try { setAlert(await api(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) })) } catch (e) { setError(e.message) } finally { setBusy(false) } }
  if (error) return <ErrorBanner message={error} onRetry={load} />
  if (!alert) return <LoadingPage />
  return <><PageHeading eyebrow="ALERT INVESTIGATION" title={alert.title} description={`${alert.category} · detected ${fmtDate(alert.occurred_at)}`} action={<Link to="/alerts" className="button secondary">Back to alerts</Link>} /><section className="panel alert-detail-panel"><div className="alert-detail-head"><div><SeverityPill severity={alert.severity} /><span className="method-tag"><Fingerprint size={13} /> {alert.method}</span></div><StatusPill status={alert.status} /></div><p className="alert-description">{alert.description}</p><div className="detail-facts"><Fact label="Rule identifier" value={`${alert.rule_id} · version ${alert.rule_version}`} /><Fact label="Detection method" value={alert.detection_type} /><Fact label="Source analysis" value={alert.job_id} link={`/analyses/${alert.job_id}`} /><Fact label="Observed at" value={fmtDate(alert.occurred_at)} /></div><h3 className="subheading">Evidence</h3><div className="evidence-grid evidence-detail">{Object.entries(alert.evidence || {}).map(([key, value]) => <Fact key={key} label={key.replaceAll('_', ' ')} value={Array.isArray(value) ? value.join(', ') : String(value)} />)}</div>{alert.indicator_context?.length > 0 && <div className="indicator-note"><ShieldCheck size={13} /> Local indicator context: {alert.indicator_context.map(item => `${item.indicator} (${item.source})`).join(', ')}</div>}{admin && <div className="alert-actions"><span>Workflow status</span>{['open', 'acknowledged', 'resolved'].map(status => <button key={status} disabled={busy || alert.status === status} className={cx('button', alert.status === status ? 'button-muted' : 'secondary')} onClick={() => updateStatus(status)}>{alert.status === status && <Check size={14} />}{status}</button>)}</div>}</section></>
}

function Fact({ label, value, link }) { return <div className="fact"><span>{label}</span>{link ? <Link to={link}>{value}</Link> : <b>{value}</b>}</div> }

function UsersPage({ currentUser }) {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ username: '', password: '', role: 'normal_user' })
  const [busy, setBusy] = useState(false)
  const load = useCallback(() => { setLoading(true); api('/users').then(rows => { setUsers(rows); setError('') }).catch(e => setError(e.message)).finally(() => setLoading(false)) }, [])
  useEffect(() => { load() }, [load])
  async function create(event) { event.preventDefault(); setBusy(true); setError(''); try { await api('/users', { method: 'POST', body: JSON.stringify(form) }); setForm({ username: '', password: '', role: 'normal_user' }); load() } catch (e) { setError(e.message) } finally { setBusy(false) } }
  async function toggle(user) { try { await api(`/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ active: !user.active }) }); load() } catch (e) { setError(e.message) } }
  async function changeRole(user, role) { try { await api(`/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ role }) }); load() } catch (e) { setError(e.message) } }
  return <><PageHeading title="User management" description="Create accounts, assign project roles, and disable access when needed." />{error && <ErrorBanner message={error} onRetry={load} />}<div className="admin-columns"><section className="panel"><div className="panel-heading"><div><span className="panel-kicker">NEW ACCOUNT</span><h2>Create a user</h2></div></div><form onSubmit={create} className="form-stack user-form"><label>Username<input required minLength={3} maxLength={64} value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></label><label>Temporary password<input type="password" required minLength={8} maxLength={128} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></label><label>Role<select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}><option value="normal_user">Normal User</option><option value="administrator">Administrator</option></select></label><button className="button primary" disabled={busy}>{busy ? 'Creating…' : 'Create account'} <ArrowUpRight size={15} /></button></form></section><section className="panel table-panel"><div className="panel-heading"><div><span className="panel-kicker">ACCESS CONTROL</span><h2>Project users</h2></div><span className="admin-view"><Users size={14} /> {users.length} ACCOUNTS</span></div>{loading ? <div className="table-state"><LoaderCircle className="spin" size={18} /> Loading accounts…</div> : users.length ? <div className="table-scroll"><table><thead><tr><th>ACCOUNT</th><th>ROLE</th><th>STATUS</th><th>CREATED</th><th></th></tr></thead><tbody>{users.map(account => { const self = account.id === currentUser.id; return <tr key={account.id}><td><b>{account.username}</b>{self && <small className="muted-text"> (you)</small>}</td><td><select className="table-select" value={account.role} disabled={self} aria-label={`Role for ${account.username}`} onChange={e => changeRole(account, e.target.value)}><option value="normal_user">Normal User</option><option value="administrator">Administrator</option></select></td><td><span className={cx('user-status', account.active ? 'active' : 'inactive')}>{account.active ? 'Active' : 'Disabled'}</span></td><td>{fmtDate(account.created_at)}</td><td><button className="text-button" disabled={self} onClick={() => toggle(account)}>{account.active ? 'Disable' : 'Enable'}</button></td></tr> })}</tbody></table></div> : <EmptyState icon={Users} title={error ? 'Accounts unavailable' : 'No accounts found'} description={error ? 'The account list could not be loaded.' : 'Create a user account to grant project access.'} />}</section></div></>
}

function AlertList({ alerts, loading, unavailable = false }) {
  if (loading) return <div className="table-state"><LoaderCircle className="spin" size={18} /> Loading alert feed…</div>
  if (unavailable) return <div className="table-state">Alert feed is unavailable. Retry after checking the connection.</div>
  if (!alerts.length) return <div className="empty-compact"><ShieldCheck size={18} /><span>No alerts recorded</span></div>
  return <div className="mini-alerts">{alerts.map(alert => <Link key={alert.id} to={`/alerts/${alert.id}`} className="mini-alert"><span className={`severity-dot ${alert.severity}`} /><span className="mini-alert-copy"><b>{alert.title}</b><small>{alert.category} · {fmtDate(alert.occurred_at)}</small></span><SeverityPill severity={alert.severity} /></Link>)}</div>
}

function StatusPill({ status }) { return <span className={`status-pill ${status || 'unknown'}`}><i />{status || 'unknown'}</span> }
function SeverityPill({ severity }) { return <span className={`severity-pill ${severity || 'low'}`}><i />{severity || 'unknown'}</span> }
function EmptyState({ icon: Icon, title, description }) { return <div className="empty-state"><div className="empty-icon"><Icon size={20} /></div><b>{title}</b><p>{description}</p></div> }
function ErrorBanner({ message, onRetry }) { return <div className="error-banner" role="alert"><AlertTriangle size={16} /><span>{message}</span>{onRetry && <button onClick={onRetry}>Retry</button>}</div> }
function LoadingPage() { return <div className="loading-page"><LoaderCircle className="spin" size={20} /> Loading workspace data…</div> }
function NotFound() { return <EmptyState icon={FileSearch} title="Page not found" description="The requested workspace page is unavailable." /> }

export default App
