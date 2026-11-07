// Sign-in with password plus a passkey, or plus an authenticator code. Without this
// script the form still works with a code.
const form = document.getElementById('login')
const codeRow = document.getElementById('code-row')
const code = document.getElementById('code')
const passkeyField = document.getElementById('passkey')
const submit = document.getElementById('submit')
const switcher = document.getElementById('switch')
const errorBox = document.getElementById('passkey-error')

const toBytes = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

let usePasskey = form.dataset.passkeys === 'yes' && 'PublicKeyCredential' in window

function showMode() {
  if (codeRow) codeRow.hidden = usePasskey
  if (code) code.required = !usePasskey
  submit.textContent = usePasskey ? 'Sign in with passkey' : 'Sign in'
  if (switcher) {
    switcher.hidden = form.dataset.passkeys !== 'yes'
    switcher.textContent = usePasskey ? 'Use an authenticator code instead' : 'Use a passkey instead'
  }
}

switcher?.addEventListener('click', () => {
  usePasskey = !usePasskey
  errorBox.hidden = true
  showMode()
})

form.addEventListener('submit', async (event) => {
  passkeyField.value = ''
  if (!usePasskey) return
  event.preventDefault()
  if (!form.reportValidity()) return
  errorBox.hidden = true
  submit.disabled = true
  try {
    const options = await (await fetch('/login/challenge', { credentials: 'same-origin' })).json()
    const credential = await navigator.credentials.get({
      publicKey: { challenge: toBytes(options.challenge), rpId: options.rpId, timeout: options.timeout, userVerification: 'preferred' },
    })
    const response = credential.response
    passkeyField.value = JSON.stringify({
      id: credential.id,
      clientDataJSON: toText(response.clientDataJSON),
      authenticatorData: toText(response.authenticatorData),
      signature: toText(response.signature),
    })
    form.submit()
  } catch (err) {
    errorBox.textContent = err?.name === 'NotAllowedError' ? 'The passkey request was cancelled or timed out.' : 'This passkey could not be used.'
    errorBox.hidden = false
    submit.disabled = false
  }
})

showMode()
