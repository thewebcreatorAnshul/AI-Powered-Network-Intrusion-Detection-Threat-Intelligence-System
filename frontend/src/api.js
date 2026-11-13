const API_BASE = import.meta.env?.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api/v1'

export function token() { return localStorage.getItem('access_token') }

function requestHeaders(options = {}) {
  const headers = new Headers(options.headers || {})
  if (token()) headers.set('Authorization', `Bearer ${token()}`)
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  return headers
}

async function requestResponse(path, options = {}) {
  let response
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers: requestHeaders(options) })
  } catch (error) {
    if (error.name === 'AbortError') throw error
    throw new Error('Unable to reach the API. Check the backend connection and retry.')
  }
  if (response.status === 204) return null
  if (!response.ok) {
    const contentType = response.headers.get('content-type') || ''
    let payload
    try { payload = contentType.includes('application/json') ? await response.json() : await response.text() }
    catch { payload = null }
    if (response.status === 401) {
      localStorage.removeItem('access_token')
      window.dispatchEvent(new Event('session-expired'))
    }
    const error = new Error(payload?.error?.message || `Request failed (${response.status})`)
    error.status = response.status
    throw error
  }
  return response
}

async function request(path, options = {}) {
  const response = await requestResponse(path, options)
  if (response === null) return null
  const contentType = response.headers.get('content-type') || ''
  let payload
  try { payload = contentType.includes('application/json') ? await response.json() : await response.text() }
  catch { payload = null }
  return payload
}

export async function api(path, options = {}) {
  return request(path, options)
}

export function uploadFile(path, body, onProgress = () => {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${API_BASE}${path}`)
    const bearer = token()
    if (bearer) xhr.setRequestHeader('Authorization', `Bearer ${bearer}`)
    xhr.upload.addEventListener('progress', event => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100))
    })
    xhr.addEventListener('error', () => reject(new Error('Unable to reach the API. Check the backend connection and retry.')))
    xhr.addEventListener('abort', () => reject(new Error('The upload was cancelled.')))
    xhr.addEventListener('load', () => {
      const contentType = xhr.getResponseHeader('content-type') || ''
      let payload
      try { payload = contentType.includes('application/json') ? JSON.parse(xhr.responseText) : xhr.responseText }
      catch { payload = null }
      if (xhr.status >= 200 && xhr.status < 300) { resolve(payload); return }
      if (xhr.status === 401) {
        localStorage.removeItem('access_token')
        window.dispatchEvent(new Event('session-expired'))
      }
      reject(Object.assign(new Error(payload?.error?.message || `Request failed (${xhr.status})`), { status: xhr.status }))
    })
    xhr.send(body)
  })
}

export async function downloadFile(path, fallbackName) {
  const response = await requestResponse(path, { method: 'GET' })
  if (response === null) throw new Error('The export was empty.')
  const disposition = response.headers.get('content-disposition') || ''
  const match = disposition.match(/filename="?([^";]+)"?/i)
  return { blob: await response.blob(), filename: match?.[1] || fallbackName }
}

export function saveDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function query(values) {
  const params = new URLSearchParams()
  Object.entries(values).forEach(([key, value]) => { if (value !== '' && value != null) params.set(key, value) })
  const result = params.toString()
  return result ? `?${result}` : ''
}
