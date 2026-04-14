using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;

namespace HmacSignature
{
    public sealed class HmacSignatureOptions
    {
        public string SignatureHeaderName { get; set; } = "X-Signature";
        public string ClientIdHeaderName { get; set; } = "X-Client-Id";
        public string TimestampHeaderName { get; set; } = "X-Timestamp";
        public string NonceHeaderName { get; set; } = "X-Nonce";

        public Func<string, Task<string?>> SecretResolverAsync { get; set; } = _ => Task.FromResult<string?>(null);

        public bool RejectUtf8Bom { get; set; } = true;
        public bool WriteProblemJson { get; set; } = true;
        public bool IncludeQueryInPath { get; set; } = false;
        public List<PathString> SkipPathPrefixes { get; } = new();

        public bool EnableTimestampValidation { get; set; } = true;
        public TimeSpan TimestampSkew { get; set; } = TimeSpan.FromMinutes(10);

        public bool EnableNonceValidation { get; set; } = false;
        public TimeSpan NonceTtl { get; set; } = TimeSpan.FromMinutes(10);
        public Func<string, string, TimeSpan, Task<bool>>? NonceValidator { get; set; } = null;

        public bool IncludeHeadersInSignature { get; set; } = false;
        public bool BodyOnlySignature { get; set; } = false;
    }

    public static class HmacSignatureExtensions
    {
        public static IApplicationBuilder UseHmacSignatureVerification(this IApplicationBuilder app, Action<HmacSignatureOptions> configure)
        {
            var opt = new HmacSignatureOptions();
            configure(opt);
            return app.UseMiddleware<HmacSignatureMiddleware>(opt);
        }
    }

    public sealed class HmacSignatureMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly HmacSignatureOptions _opt;
        public const string HttpItemsClientIdKey = "ClientId";

        public HmacSignatureMiddleware(RequestDelegate next, HmacSignatureOptions opt)
        {
            _next = next;
            _opt = opt;
        }

        public async Task Invoke(HttpContext ctx)
        {
            if (_opt.SkipPathPrefixes.Any(p => ctx.Request.Path.StartsWithSegments(p)))
            {
                await _next(ctx);
                return;
            }

            if (_opt.EnableTimestampValidation)
            {
                if (!ctx.Request.Headers.TryGetValue(_opt.TimestampHeaderName, out var hTs) ||
                    !long.TryParse(hTs, out long ts))
                {
                    await Reject(ctx, 401, "invalid_timestamp", $"{_opt.TimestampHeaderName} must be unix epoch seconds.", _opt.WriteProblemJson);
                    return;
                }

                var reqTime = DateTimeOffset.FromUnixTimeSeconds(ts);
                var delta = (DateTimeOffset.UtcNow - reqTime).Duration();

                if (delta > _opt.TimestampSkew)
                {
                    await Reject(ctx, 401, "timestamp_window", $"Request timestamp outside acceptable window.", _opt.WriteProblemJson);
                    return;
                }
            }

            if (!ctx.Request.Headers.TryGetValue(_opt.ClientIdHeaderName, out var hClient) || string.IsNullOrWhiteSpace(hClient))
            {
                await Reject(ctx, 401, "missing_client_id", $"{_opt.ClientIdHeaderName} is required.", _opt.WriteProblemJson);
                return;
            }

            if (!ctx.Request.Headers.TryGetValue(_opt.SignatureHeaderName, out var hSigRaw))
            {
                await Reject(ctx, 401, "missing_signature", $"{_opt.SignatureHeaderName} is required.", _opt.WriteProblemJson);
                return;
            }

            var sigStr = hSigRaw.ToString();
            if (!sigStr.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase))
            {
                await Reject(ctx, 401, "invalid_signature_format", $"{_opt.SignatureHeaderName} must start with 'sha256='.", _opt.WriteProblemJson);
                return;
            }
            var providedHex = sigStr.Substring("sha256=".Length).Trim();

            string? nonce = null;
            if (_opt.EnableNonceValidation)
            {
                if (!ctx.Request.Headers.TryGetValue(_opt.NonceHeaderName, out var hNonce) || string.IsNullOrWhiteSpace(hNonce))
                {
                    await Reject(ctx, 401, "missing_nonce", $"{_opt.NonceHeaderName} is required.", _opt.WriteProblemJson);
                    return;
                }
                nonce = hNonce.ToString();

                if (_opt.NonceValidator != null)
                {
                    var firstUse = await _opt.NonceValidator(hClient.ToString(), nonce, _opt.NonceTtl);
                    if (!firstUse)
                    {
                        await Reject(ctx, 401, "replay_detected", "Nonce already used.", _opt.WriteProblemJson);
                        return;
                    }
                }
            }

            var secret = await _opt.SecretResolverAsync(hClient.ToString());
            if (string.IsNullOrEmpty(secret))
            {
                await Reject(ctx, 401, "unknown_client", "Unknown client id.", _opt.WriteProblemJson);
                return;
            }

            string bodyRaw;
            try
            {
                ctx.Request.EnableBuffering();
                ctx.Request.Body.Position = 0;
                using var ms = new MemoryStream();
                await ctx.Request.Body.CopyToAsync(ms);
                ctx.Request.Body.Position = 0;
                bodyRaw = Encoding.UTF8.GetString(ms.ToArray());

                var bytes = ms.ToArray();
                if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
                {
                    if (_opt.RejectUtf8Bom)
                    {
                        await Reject(ctx, 415, "utf8_bom_rejected", "UTF-8 BOM is not allowed.", _opt.WriteProblemJson);
                        return;
                    }
                    else
                    {
                        bytes = bytes[3..];
                    }
                }
            }
            catch
            {
                await Reject(ctx, 400, "read_body_failed", "Failed to read request body.", _opt.WriteProblemJson);
                return;
            }

            var method = ctx.Request.Method.ToUpperInvariant();
            var pathOnly = _opt.IncludeQueryInPath
                ? ctx.Request.Path + ctx.Request.QueryString.ToUriComponent()
                : ctx.Request.Path.ToString();

            string signingString;
            if (_opt.BodyOnlySignature)
            {
                signingString = bodyRaw;
            }
            else if (_opt.IncludeHeadersInSignature)
            {
                var tsString = ctx.Request.Headers.TryGetValue(_opt.TimestampHeaderName, out var hTs2) ? hTs2.ToString() : "";
                signingString = $"{pathOnly}\n{method}\n{bodyRaw}\n{hClient}\n{nonce ?? ""}\n{tsString}";
            }
            else
            {
                signingString = $"{pathOnly}\n{method}\n{bodyRaw}";
            }

            var computedHex = ComputeHmacHex(secret, signingString);

            if (!FixedTimeEqualsHex(providedHex, computedHex))
            {
                await Reject(ctx, 401, "signature_mismatch", "Signature is invalid.", _opt.WriteProblemJson);
                return;
            }

            ctx.Items[HttpItemsClientIdKey] = hClient.ToString();
            await _next(ctx);
        }

        private static string ComputeHmacHex(string secret, string data)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private static bool FixedTimeEqualsHex(string a, string b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static async Task Reject(HttpContext ctx, int status, string code, string msg, bool writeJson)
        {
            ctx.Response.StatusCode = status;
            if (!writeJson) return;
            ctx.Response.ContentType = "application/json; charset=utf-8";

            var payload = JsonSerializer.Serialize(new
            {
                error = new { code, message = msg },
                ts = DateTimeOffset.UtcNow.ToString("O")
            });
            await ctx.Response.WriteAsync(payload, Encoding.UTF8);
        }
    }
}