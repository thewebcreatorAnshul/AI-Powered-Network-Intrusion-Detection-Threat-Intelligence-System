import { afterEach, beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { api, downloadFile, query, saveDownload, uploadFile } from '../src/api.js'

let values
let expiredEvents
let originalFetch
let originalStorage
let originalWindow

beforeEach(() => {
  values = new Map()
  expiredEvents = 0
  originalFetch = globalThis.fetch
  originalStorage = globalThis.localStorage
  originalWindow = globalThis.window
  globalThis.localStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: key => values.delete(key),
  }
  globalThis.window = { dispatchEvent(event) { if (event.type === 'session-expired') expiredEvents++ }, setTimeout }
})

afterEach(() => {
  globalThis.fetch = originalFetch
  globalThis.localStorage = originalStorage
  globalThis.window = originalWindow
})

test('query omits empty values and URL encodes selected filters', () => {
  assert.equal(query({ q: 'syn scan', status: '', skip: 0, since: null }), '?q=syn+scan&skip=0')
})

test('api sends bearer token and parses JSON', async () => {
  values.set('access_token', 'test-token')
  globalThis.fetch = async (url, options) => {
    assert.match(url, /\/analyses\?limit=5$/)
    assert.equal(options.headers.get('Authorization'), 'Bearer test-token')
    return new Response(JSON.stringify([{ id: 'job-1' }]), { headers: { 'content-type': 'application/json' } })
  }
  assert.deepEqual(await api('/analyses?limit=5'), [{ id: 'job-1' }])
})

test('401 clears local token and signals the application session handler', async () => {
  values.set('access_token', 'test-token')
  globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: 'Session revoked.' } }), {
    status: 401, headers: { 'content-type': 'application/json' },
  })
  await assert.rejects(api('/auth/me'), /Session revoked/)
  assert.equal(values.has('access_token'), false)
  assert.equal(expiredEvents, 1)
})

test('204 returns null and network errors are actionable', async () => {
  globalThis.fetch = async () => new Response(null, { status: 204 })
  assert.equal(await api('/auth/logout'), null)
  globalThis.fetch = async () => { throw new TypeError('offline') }
  await assert.rejects(api('/dashboard'), /Unable to reach the API/)
})

test('download reads the response as a blob and uses its filename', async () => {
  values.set('access_token', 'test-token')
  globalThis.fetch = async (_url, options) => {
    assert.equal(options.headers.get('Authorization'), 'Bearer test-token')
    return new Response('id,title\n1,test\n', { headers: {
      'content-type': 'text/csv', 'content-disposition': 'attachment; filename="alerts.csv"',
    } })
  }
  const result = await downloadFile('/alerts/export', 'fallback.csv')
  assert.equal(result.filename, 'alerts.csv')
  assert.equal(await result.blob.text(), 'id,title\n1,test\n')
})

test('upload reports progress, attaches auth and parses the accepted job', async () => {
  values.set('access_token', 'upload-token')
  const calls = []
  class FakeXHR {
    constructor() { this.listeners = {}; this.upload = { addEventListener: (name, fn) => { this.progress = fn } } }
    open(method, url) { this.method = method; this.url = url }
    setRequestHeader(name, value) { this.headers = { ...this.headers, [name]: value } }
    addEventListener(name, fn) { this.listeners[name] = fn }
    getResponseHeader() { return 'application/json' }
    send(body) {
      this.body = body
      this.progress({ lengthComputable: true, loaded: 5, total: 10 })
      this.status = 202
      this.responseText = JSON.stringify({ id: 'job-123' })
      this.listeners.load()
    }
  }
  const originalXHR = globalThis.XMLHttpRequest
  globalThis.XMLHttpRequest = FakeXHR
  try {
    const result = await uploadFile('/analyses', new FormData(), value => calls.push(value))
    assert.deepEqual(result, { id: 'job-123' })
    assert.deepEqual(calls, [50])
  } finally { globalThis.XMLHttpRequest = originalXHR }
})

test('upload surfaces server validation failures without losing the HTTP status', async () => {
  class ErrorXHR {
    constructor() { this.listeners = {}; this.upload = { addEventListener() {} } }
    open() {}
    addEventListener(name, fn) { this.listeners[name] = fn }
    getResponseHeader() { return 'application/json' }
    send() { this.status = 413; this.responseText = JSON.stringify({ error: { message: 'Capture exceeds the upload limit.' } }); this.listeners.load() }
  }
  const originalXHR = globalThis.XMLHttpRequest
  globalThis.XMLHttpRequest = ErrorXHR
  try {
    await assert.rejects(uploadFile('/analyses', new FormData()), error => {
      assert.equal(error.status, 413)
      assert.match(error.message, /upload limit/)
      return true
    })
  } finally { globalThis.XMLHttpRequest = originalXHR }
})

test('download saver creates and revokes a temporary object URL', () => {
  const originalURL = globalThis.URL
  const originalDocument = globalThis.document
  let clicked = false
  let revoked = ''
  globalThis.URL = { createObjectURL: () => 'blob:test', revokeObjectURL: value => { revoked = value } }
  globalThis.document = { body: { appendChild() {} }, createElement: () => ({ click() { clicked = true }, remove() {} }) }
  try {
    saveDownload(new Blob(['ok']), 'report.csv')
    assert.equal(clicked, true)
  } finally { globalThis.URL = originalURL; globalThis.document = originalDocument }
})
