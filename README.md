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
2. `dotnet nuget push src/bin/Debug/Nutonomy.Auto0AutoRest.1.0.0.nupkg -k <apikey> --source https://www.nuget.org/api/v2/package`