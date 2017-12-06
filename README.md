## Auth0 Token provider for AutoRest

### Example usage

Look at `test/Auth0AutoRestTest`

### Unit tests

In `test/`, run
```
dotnet test
```

### Publish the package

1. `dotnet pack`
2. `dotnet nuget push src/bin/Debug/Nutonomy.Auth0AutoRest.<PackageVersion>.nupkg -k <apikey> --source https://www.nuget.org/api/v2/package
`