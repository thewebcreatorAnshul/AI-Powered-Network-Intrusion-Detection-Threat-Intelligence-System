const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api/v1'

export function token() { return localStorage.getItem('access_token') }

export async function api(path, options = {}) {
  const headers = new Headers(options.headers || {})
  if (token()) headers.set('Authorization', `Bearer ${token()}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers })
  if (response.status === 204) return null
  const contentType = response.headers.get('content-type') || ''
  const payload = contentType.includes('application/json') ? await response.json() : await response.text()
  if (!response.ok) {
    if (response.status === 401) {
      localStorage.removeItem('access_token')
      window.dispatchEvent(new Event('session-expired'))
    }
    throw new Error(payload?.error?.message || `Request failed (${response.status})`)
  }
  return payload
}

export function query(values) {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => { if (value !== '' && value != null) params.set(key, value) })
  const result = params.toString()
  return result ? `?${result}` : ''
}
