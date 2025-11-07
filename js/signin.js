// js/signin.js
const clientId = 'YOUR_COGNITO_APP_CLIENT_ID';
const clientSecret = 'YOUR_COGNITO_APP_CLIENT_SECRET';
const region = 'YOUR_AWS_REGION';

// Compute SECRET_HASH
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

// Handle sign in
async function signInUser() {
  const username = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  const secretHash = await getSecretHash(username);

  AWS.config.region = region;
  const cognito = new AWS.CognitoIdentityServiceProvider();

  const params = {
    AuthFlow: 'USER_PASSWORD_AUTH',
    ClientId: clientId,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      SECRET_HASH: secretHash
    }
  };

  cognito.initiateAuth(params, function (err, data) {
    if (err) {
      alert('Error: ' + err.message);
    } else {
      console.log('Login success:', data);
      alert('Login successful!');
    }
  });
}

document.getElementById('signinBtn').addEventListener('click', signInUser);
