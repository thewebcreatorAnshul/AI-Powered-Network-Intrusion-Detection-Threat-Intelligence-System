const STATUS_ACTIONS = {
  open: [
    { status: 'acknowledged', label: 'Acknowledge' },
    { status: 'resolved', label: 'Resolve' },
  ],
  acknowledged: [
    { status: 'resolved', label: 'Resolve' },
  ],
  resolved: [
    { status: 'open', label: 'Reopen' },
  ],
}

export function alertStatusActions(status) {
  return STATUS_ACTIONS[status] || []
}
