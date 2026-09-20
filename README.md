# @halocache/halo-mcc-auth

Xbox Live authentication implementing the SISU flow

### Basic Interactive Authentication

```javascript
import { XboxAuth } from '@halocache/halo-mcc-auth';

// Initialize the client.
// `sessionName` is REQUIRED — it namespaces the cached token files, so several
// accounts can share one cache directory. It is not a Microsoft account name.
const auth = new XboxAuth({
    sessionName: 'default',
    // Optional: custom cache location.
    // Contains an ECDSA private key and a refresh token — treat as secrets.
    cacheDir: './.cache/auth',
    // Optional: libraries are silent unless a logger is supplied.
    logger: console
});

// Step 1: Start the Interactive Flow
// This generates the correct SISU URL for the user to visit
const { authUrl } = await auth.beginInteractiveAuth();
console.log(`Please sign in here: ${authUrl}`);

// ...
// Application waits for user to sign in and copy the callback URL/Code
// ...

// Step 2: Complete the Flow
// Pass the authorization code (or full redirect URL) provided by Microsoft
await auth.completeInteractiveAuth(userProvidedCode);

console.log('Authentication Successful!');
```

### Acquiring Tokens for API Requests

Once authenticated, getting a valid `XSTS` token is simple. The library handles validity checks and refreshing automatically.

```javascript
// Get a token for the Halo MCC Title Service (standard XSTS)
const tokenData = await auth.getXboxToken('http://xboxlive.com');

console.log(`XUID: ${tokenData.userXUID}`);
console.log(`Header Value: ${tokenData.tokenString}`); // "XBL3.0 x=...;..."

// Use it in your API calls
// await fetch('https://example.com/api', {
//   headers: { Authorization: tokenData.tokenString }
// });
```

### Verified Authentication Flow

1.  **Device Authentication** (`/device/authenticate`):
    *   Generates a persistent ECDSA keypair (P-256).
    *   Obtains a `DeviceToken` bound to this key.
    *   *Verified*: Returns `DisplayClaims.xdi` containing the Device ID.

2.  **SISU Handshake** (`/authenticate`):
    *   Initiates the OAuth2 flow using the `DeviceToken`.
    *   Returns a `SessionId` (header) and `MsaOauthRedirect` URL.

3.  **User Authentication** (OAuth2):
    *   User signs in via browser.
    *   Standard Authorization Code flow + PKCE.
    *   Returns `access_token` (prefixed with `d=` for SISU).

4.  **SISU Authorization** (`/authorize`):
    *   *Critical Step*: Exchanges the OAuth `access_token` AND a **FRESH** `DeviceToken` for Xbox tokens.
    *   Returns `UserToken` (JWT), `TitleToken` (JWT), and `DeviceToken`.
    *   *Note*: Reusing the initial Device Token here results in a **403 Forbidden**.

5.  **XSTS Authorization** (`/xsts/authorize`):
    *   Exchanges the User/Title/Device tokens for a final `XSTS` token.
    *   Returns the `uhs` (User Hash) and `Token` required for API headers.

6.  **PlayFab Login** (`/Client/LoginWithXbox`):
    *   Uses the XSTS token to log into PlayFab.
    *   Returns `SessionTicket` and `EntityToken` (with `TokenExpiration`).

## Troubleshooting & Common Errors

*   **SISU 403 Forbidden**: Usually occurs during `SISU Authorize` if the Device Token used is "stale" (i.e., was already used for the initial handshake). The library automatically handles this by generating a fresh Device Token.
*   **OAuth 400 Bad Request**: Often due to PKCE mismatch. Ensure `code_verifier` is persisted correctly between the `begin` and `complete` phases.
*   **"Authentication required"**: Indicates that the cached tokens have expired and the refresh token is invalid or missing. Interactive login is required.

## Contributing

Contributions, issues, and feature requests are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
