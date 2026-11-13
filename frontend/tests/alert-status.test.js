import { test } from 'node:test'
import assert from 'node:assert/strict'
import { alertStatusActions } from '../src/alertStatus.js'

test('open alerts can be acknowledged or resolved', () => {
  assert.deepEqual(alertStatusActions('open').map(action => action.status), ['acknowledged', 'resolved'])
})

test('acknowledged alerts can be resolved', () => {
  assert.deepEqual(alertStatusActions('acknowledged').map(action => action.status), ['resolved'])
})

test('resolved alerts can be reopened', () => {
  assert.deepEqual(alertStatusActions('resolved'), [{ status: 'open', label: 'Reopen' }])
})

test('unknown states expose no actions', () => {
  assert.deepEqual(alertStatusActions('unknown'), [])
})
