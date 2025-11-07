// js/register.js
const clientId = 'YOUR_COGNITO_APP_CLIENT_ID';
const clientSecret = 'YOUR_COGNITO_APP_CLIENT_SECRET';
const region = 'YOUR_AWS_REGION';
const poolId = 'YOUR_USER_POOL_ID';

// Compute SECRET_HASH using HMAC-SHA256
function getSecretHash(username) {
  const crypto = window.crypto.subtle;
  const enc = new TextEncoder();
  const keyData = enc.encode(clientSecret);
  const msg = enc.encode(username + clientId);
  return crypto.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    .then(key => crypto.sign('HMAC', key, msg))
    .then(sig => {
      const hashArray = Array.from(new Uint8Array(sig));
      const base64 = btoa(String.fromCharCode.apply(null, hashArray));
      return base64;
    });
}

// Handle registration
async function registerUser() {
  const username = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  const secretHash = await getSecretHash(username);

  const params = {
    ClientId: clientId,
    Username: username,
    Password: password,
    SecretHash: secretHash
  };

  AWS.config.region = region;
  const cognito = new AWS.CognitoIdentityServiceProvider();

  cognito.signUp(params, function (err, data) {
    if (err) {
      alert('Error: ' + err.message);
    } else {
      alert('Registration successful! Please verify your email.');
      console.log('SignUp success:', data);
    }
  });
}

document.getElementById('registerBtn').addEventListener('click', registerUser);
