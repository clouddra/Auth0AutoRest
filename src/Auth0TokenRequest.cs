using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace Auth0AutoRest
{
    public class Auth0TokenRequest
    {
        [Required]
        [JsonProperty("client_id")]
        public string ClientId { get; set; }

        [Required]
        [JsonProperty("client_secret")]
        public string ClientSecret { get; set; }

        [Required]
        [JsonProperty("audience")]
        public string Audience { get; set; }

        [Required]
        [JsonProperty("grant_type")]
        public string GrantType { get; set; } = "client_credentials";
    }
}