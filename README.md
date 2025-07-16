# Owl.TokenWildcardIssuerValidator 

A lightweight .NET library designed to enhance JWT token validation in ASP.NET Core applications by enabling support for wildcard issuer (iss) validation.

[![Nuget](https://img.shields.io/nuget/v/Owl.TokenWildcardIssuerValidator?style=plastic)](https://www.nuget.org/packages/Owl.TokenWildcardIssuerValidator)


You can set [TokenValidationParameters's](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters) [IssuerValidator](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.issuervalidator) or [IssuerValidatorUsingConfiguration](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters.issuervalidatorusingconfiguration) to support wildcard issuer validation.

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

```cs
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://abp.io";
        options.Audience = "abp_io";

        options.TokenValidationParameters.IssuerValidatorUsingConfiguration = TokenWildcardIssuerValidator.IssuerValidatorUsingConfiguration;
        options.TokenValidationParameters.ValidIssuers = new[]
        {
            "https://{0}.abp.io"
        };
    });
```
