using System;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Flurl.Http;
using Microsoft.Rest;
using Newtonsoft.Json;

namespace Auth0AutoRest
{
    public class Auth0Provider : ITokenProvider
    {
        public TimeSpan TokenTimeout { get; }
        private readonly Auth0TokenRequest _auth0TokenRequest;
        private Auth0TokenResponse _cachedToken;
        private DateTime _expiry;
        private bool _isAuthRequired;
        private readonly string _cachedTokenResponse = @"/tmp/tokenResponse.json";
        public Auth0Provider(Auth0TokenRequest auth0TokenRequest, bool isAuthRequired = true) : this(auth0TokenRequest, TimeSpan.FromMinutes(10), isAuthRequired)
        {
        }

        public Auth0Provider(Auth0TokenRequest auth0TokenRequest, TimeSpan tokenTimeout, bool isAuthRequired = true)
        {
            TokenTimeout = tokenTimeout;
            _auth0TokenRequest = auth0TokenRequest;
            _isAuthRequired = isAuthRequired;
        }

        private DateTime GetExpiry(Auth0TokenResponse tokenResponse)
        {
            var exp = new JwtSecurityTokenHandler().ReadJwtToken(tokenResponse.AccessToken).Payload.Exp;
            var offset = exp == null ? 0 : (long)exp;
            return DateTimeOffset.FromUnixTimeSeconds(offset).UtcDateTime;
        }

        public async Task<AuthenticationHeaderValue> GetAuthenticationHeaderAsync(CancellationToken cancellationToken)
        {
            if (_isAuthRequired)
            {
                if (_cachedToken == null)
                {
                    // get token if found in tmp folder
                    if (File.Exists(_cachedTokenResponse))
                    {
                        using (var streamReader = new StreamReader(_cachedTokenResponse))
                        {
                            var responseJson = streamReader.ReadToEnd();
                            try
                            {
                                var cachedTokenResponse = JsonConvert.DeserializeObject<Auth0TokenResponse>(responseJson);
                                _expiry = GetExpiry(cachedTokenResponse);
                                _cachedToken = cachedTokenResponse;
                            }
                            catch (Exception)
                            { }
                        }
                    }
                }

                // only renew token if doesn't exist in cache or tmp folder or if it is nearing expiry
                if (_cachedToken == null || DateTime.UtcNow + TokenTimeout > _expiry)
                {
                    var tokenResponse = await _auth0TokenRequest.Auth0Endpoint
                        .PostJsonAsync(_auth0TokenRequest)
                        .ReceiveJson<Auth0TokenResponse>();
                    var jsonString = JsonConvert.SerializeObject(tokenResponse);
                    if (Directory.Exists(@"/tmp"))
                    {
                        File.WriteAllText(_cachedTokenResponse, jsonString);
                    }
                    _expiry = GetExpiry(tokenResponse);
                    _cachedToken = tokenResponse;
                }
                return _cachedToken.AuthenticationHeader;
            }
            else
            {
                return new AuthenticationHeaderValue("Bearer", "Not getting token from Auth0 when isAuthRequired=false (env=Development)");
            }
        }
    }
}