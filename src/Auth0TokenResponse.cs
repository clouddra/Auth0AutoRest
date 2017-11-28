using System.Net.Http.Headers;
using Newtonsoft.Json;

namespace Auth0AutoRest
{
    public class Auth0TokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; } = "Bearer";

        public AuthenticationHeaderValue AuthenticationHeader =>
            new AuthenticationHeaderValue(TokenType, AccessToken);
    }
}