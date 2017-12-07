using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Flurl.Http;
using Microsoft.Rest;

namespace Auth0AutoRest
{
    public class Auth0Provider : ITokenProvider
    {
        public TimeSpan TokenTimeout { get; }
        private readonly Auth0TokenRequest _auth0TokenRequest;
        private Auth0TokenResponse _cachedToken;
        private DateTime _expiry;

        public Auth0Provider(Auth0TokenRequest auth0TokenRequest) : this(auth0TokenRequest, TimeSpan.FromMinutes(10))
        {
        }

        public Auth0Provider(Auth0TokenRequest auth0TokenRequest, TimeSpan tokenTimeout)
        {
            TokenTimeout = tokenTimeout;
            _auth0TokenRequest = auth0TokenRequest;
        }

        public async Task<AuthenticationHeaderValue> GetAuthenticationHeaderAsync(CancellationToken cancellationToken)
        {
            if (_cachedToken == null || DateTime.UtcNow + TokenTimeout > _expiry)
            {
                var tokenResponse = await _auth0TokenRequest.Auth0Endpoint
                    .PostJsonAsync(_auth0TokenRequest)
                    .ReceiveJson<Auth0TokenResponse>();

                var exp = new JwtSecurityTokenHandler().ReadJwtToken(tokenResponse.AccessToken).Payload.Exp;
                var offset = exp == null ? 0 : (long) exp;
                _expiry = DateTimeOffset.FromUnixTimeSeconds(offset).UtcDateTime;
                _cachedToken = tokenResponse;
            }

            return _cachedToken.AuthenticationHeader;
        }
    }
}