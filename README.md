# Owl.TokenWildcardIssuerValidator 

[![Nuget](https://img.shields.io/nuget/v/Owl.TokenWildcardIssuerValidator?style=plastic)](https://www.nuget.org/packages/Owl.TokenWildcardIssuerValidator)

```cs
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://abp.io";
        options.Audience = "abp_io";

        options.TokenValidationParameters.IssuerValidator = TokenWildcardIssuerValidator.IssuerValidator;
        options.TokenValidationParameters.ValidIssuers = new[]
        {
            "https://{0}.abp.io"
        };
    });
```
