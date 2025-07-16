using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Shouldly;
using Xunit;

namespace Owl.TokenWildcardIssuerValidator.Tests
{
    public class TestBaseConfiguration : BaseConfiguration
    {
        private string _issuer;

        public TestBaseConfiguration(string issuer)
        {
            _issuer = issuer;
        }

        public override string Issuer => _issuer;
    }

    public class TokenWildcardIssuerValidator_Tests
    {
        // {
        //     "alg": "HS256",
        //     "typ": "JWT"
        // }
        // {
        //     "iss": "https://api.abp.io",
        //     "sub": "1"
        // }
        private readonly JsonWebToken _token = new("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwaS5hYnAuaW8iLCJzdWIiOiIxIn0.vYg4-GBELUgTReUOnuA2lHggizMZD2si3rD_LhjDtUQ");

        private readonly TokenValidationParameters _issuerValidatorTokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidIssuer = "https://abp.io",
            ValidIssuers = new[]
            {
                "https://{0}.abp.io"
            }
        };

        private readonly TokenValidationParameters _issuerValidatorUsingConfigurationTokenValidationParameters = new()
        {
            ValidateIssuer = true
        };

        [Theory]
        [InlineData("https://abp.io")]
        [InlineData("https://www.abp.io")]
        [InlineData("https://api.abp.io")]
        [InlineData("https://t1.api.abp.io")]
        public void IssuerValidator_Valid_Test(string issuer)
        {
            TokenWildcardIssuerValidator.IssuerValidator(issuer, _token, _issuerValidatorTokenValidationParameters).ShouldBe(issuer);
        }

        [Theory]
        [InlineData("http://abp.io")]
        [InlineData("http://abp.io/")]
        [InlineData("https://api.abp.com")]
        [InlineData("http://www.abp.io")]
        [InlineData("https://abp.io.test.mydomain.com")]
        public void IssuerValidator_Invalid_Test(string issuer)
        {
            Assert.Throws<SecurityTokenInvalidIssuerException>(() => TokenWildcardIssuerValidator.IssuerValidator(issuer, _token, _issuerValidatorTokenValidationParameters));
        }

        [Theory]
        [InlineData("https://abp.io")]
        [InlineData("https://www.abp.io")]
        [InlineData("https://api.abp.io")]
        [InlineData("https://t1.api.abp.io")]
        public void IssuerValidatorUsingConfiguration_Valid_Test(string issuer)
        {
            TokenWildcardIssuerValidator.IssuerValidatorUsingConfiguration(issuer, _token, _issuerValidatorUsingConfigurationTokenValidationParameters, new TestBaseConfiguration("https://{0}.abp.io")).ShouldBe(issuer);
        }

        [Theory]
        [InlineData("http://abp.io")]
        [InlineData("http://abp.io/")]
        [InlineData("https://api.abp.com")]
        [InlineData("http://www.abp.io")]
        [InlineData("https://abp.io.test.mydomain.com")]
        public void IssuerValidatorUsingConfiguration_Invalid_Test(string issuer)
        {
            Assert.Throws<SecurityTokenInvalidIssuerException>(() => TokenWildcardIssuerValidator.IssuerValidatorUsingConfiguration(issuer, _token, _issuerValidatorUsingConfigurationTokenValidationParameters, new TestBaseConfiguration("https://abp.io")));
        }
    }
}
