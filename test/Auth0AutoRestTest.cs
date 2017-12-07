using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Auth0AutoRest;
using Flurl.Http.Testing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Auth0AutoRestTest
{
    public class Auth0TokenProviderTest
    {
        private const string Audience = "audience";
        private const string ClientId = "cliendId";
        private const string ClientSecret = "clientSecret";

        private readonly Auth0Provider _auth0TokenProvider;
        private readonly SigningCredentials _signingCredentials;

        public Auth0TokenProviderTest()
        {
            _auth0TokenProvider = new Auth0Provider(new Auth0TokenRequest
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                Audience = Audience,
                Auth0Endpoint = "https://test.auth0.com/oauth/token"
            });

            var rand = new RNGCryptoServiceProvider();
            var randBytes = new byte[16];
            rand.GetBytes(randBytes);

            _signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(randBytes),
                SecurityAlgorithms.HmacSha256Signature);
        }

        private string GenerateJwt(DateTime expiry)
        {
            return new JwtSecurityTokenHandler().CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Audience = Audience,
                SigningCredentials = _signingCredentials,
                Expires = expiry
            });
        }

        private Task<AuthenticationHeaderValue> GetMockedAuthHeader(string token)
        {
            using (var httpTest = new HttpTest())
            {
                httpTest.RespondWithJson(new Auth0TokenResponse
                {
                    AccessToken = token
                });

                return _auth0TokenProvider.GetAuthenticationHeaderAsync(default(CancellationToken));
            }
        }

        [Fact]
        public async Task GetTokenUncached()
        {
            // make sure after timeout
            var oldExpiry = DateTime.UtcNow + _auth0TokenProvider.TokenTimeout - TimeSpan.FromMinutes(5);
            var oldToken = GenerateJwt(oldExpiry);

            var newExpiry = oldExpiry + TimeSpan.FromSeconds(1);
            var newToken = GenerateJwt(newExpiry);

            var oldAuthHeader = await GetMockedAuthHeader(oldToken);
            Assert.Equal(oldToken, oldAuthHeader.Parameter);

            var newAuthHeader = await GetMockedAuthHeader(newToken);
            Assert.Equal(newToken, newAuthHeader.Parameter);
        }

        [Fact]
        public async Task GetTokenCached()
        {
            // make sure the token before timeout
            var oldExpiry = DateTime.UtcNow + _auth0TokenProvider.TokenTimeout + TimeSpan.FromHours(1);
            var oldToken = GenerateJwt(oldExpiry);

            var newExpiry = oldExpiry + TimeSpan.FromSeconds(1);
            var newToken = GenerateJwt(newExpiry);

            var oldAuthHeader = await GetMockedAuthHeader(oldToken);
            Assert.Equal(oldToken, oldAuthHeader.Parameter);

            // not fetched since it is token has not timeout
            var newAuthHeader = await GetMockedAuthHeader(newToken);
            Assert.Equal(oldToken, newAuthHeader.Parameter);
        }
    }
}