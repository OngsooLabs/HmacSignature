# HmacSignature

An HMAC-SHA256 based signature verification middleware for ASP.NET Core designed to ensure API communication integrity and prevent replay attacks.

## Key Features
* **HMAC-SHA256 Signature Verification**: Blocks payload tampering by verifying requests using a pre-shared secret key between the client and the server.
* **Timestamp Skew Validation**: Rejects requests originating from the past or future that fall outside the allowed time window.
* **Nonce-based Replay Protection**: Blocks duplicate requests with the exact same `ClientId` and `Nonce` combination, providing a robust defense against replay attacks.
* **Payload Integrity**: Incorporates the raw Request Body into the signing string to detect any packet tampering.

## Installation & Setup

Register the middleware in your `Program.cs` pipeline before the routes that require security.

```csharp
using HmacSignature;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ... other middleware ...

app.UseHmacSignatureVerification(opt =>
{
    // 1. Secret Key Resolver (Required) - Asynchronously retrieve the Secret for the ClientId
    opt.SecretResolverAsync = async (clientId) => 
    {
        // Example: return await db.GetClientSecretAsync(clientId);
        if (clientId == "test-client") return "my-super-secret-key";
        return null; 
    };

    // 2. Timestamp Validation (Recommended)
    opt.EnableTimestampValidation = true;
    opt.TimestampSkew = TimeSpan.FromMinutes(10); // Allow ±10 minutes tolerance

    // 3. Nonce Validation (For enhanced security)
    opt.EnableNonceValidation = true;
    opt.NonceTtl = TimeSpan.FromMinutes(10);
    opt.NonceValidator = async (clientId, nonce, ttl) =>
    {
        // Return true if it's the first time seeing this Nonce, false if it's a reuse.
        // Example: return await cache.IsFirstUseAsync($"nonce:{clientId}:{nonce}", ttl);
        return true; 
    };

    // 4. Signing String Options
    opt.IncludeHeadersInSignature = true; // Include ClientId, Nonce, Timestamp in the signature
    opt.IncludeQueryInPath = false;       // Exclude querystring from the signature (PATH only)
    opt.RejectUtf8Bom = true;             // Reject payloads with UTF-8 BOM
});

app.MapControllers();
app.Run();
```

## Configuration Options (HmacSignatureOptions)

| Option | Default | Description |
| :--- | :--- | :--- |
| `SignatureHeaderName` | `X-Signature` | The header name for the signature value. |
| `ClientIdHeaderName` | `X-Client-Id` | The header name for the client identifier. |
| `TimestampHeaderName` | `X-Timestamp` | The header name for the UNIX Epoch Seconds. |
| `NonceHeaderName` | `X-Nonce` | The header name for the unique nonce. |
| `SecretResolverAsync` | `null` | Async function returning the `Secret` based on `ClientId`. (Required) |
| `EnableTimestampValidation` | `true` | Whether to enable timestamp validation. |
| `EnableNonceValidation` | `false` | Whether to enable nonce reuse prevention. |
| `IncludeHeadersInSignature` | `false` | Whether to include identification headers in the signing string. |
| `BodyOnlySignature` | `false` | If `true`, ignores PATH and METHOD and only uses the raw body for signature verification. |

## Client Implementation Guide

Clients calling the API must include the following four headers:

1. `X-Client-Id`: The issued client ID.
2. `X-Timestamp`: The current UNIX Epoch Seconds.
3. `X-Nonce`: A unique random string generated per request (UUID recommended).
4. `X-Signature`: `sha256=<computed_hash_in_lowercase_hex>`

### Signing String Generation Rules

The signing string format is determined by the server's `IncludeHeadersInSignature` option. The client and server must use the exact same rules.

**Basic Format (`IncludeHeadersInSignature = false`)**
```text
{PATH}
{METHOD}
{BODY_RAW}
```

**Extended Format (`IncludeHeadersInSignature = true`)**
```text
{PATH}
{METHOD}
{BODY_RAW}
{CLIENT_ID}
{NONCE}
{TIMESTAMP}
```
*(Note: Each component is separated by a newline character `\n`. `{PATH}` varies depending on the `IncludeQueryInPath` option.)*

### cURL Example

```bash
curl -X POST [https://api.yourdomain.com/api/v1/data](https://api.yourdomain.com/api/v1/data) \
  -H "Content-Type: application/json; charset=utf-8" \
  -H "X-Client-Id: test-client" \
  -H "X-Timestamp: 1736470000" \
  -H "X-Nonce: 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Signature: sha256=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2" \
  -d '{"key":"value"}'
```

## Error Response Format

On validation failure, a `401` or `415` status code is returned along with a JSON payload:
```json
{
  "error": {
    "code": "signature_mismatch",
    "message": "Signature is invalid."
  },
  "ts": "2026-04-14T22:45:00.0000000Z"
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
