# Auth API Version 1

# Summary
- **/api/auth/validate** `to validate a bearer token before login`
- **/api/auth/login** `to validate the credentials and return a bearer token if success`
- **/api/auth/refresh** `refresh a current bearer token, and get a new bearer token if a current token is valid`
- **/api/auth/logout** `revoke a current bearer token so it can't be used anymore to access API resources`

## Detail Token
Following is an example of generated token in response body:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJpc3MiOiJrYW5nYXJvb19oZWFsdGgiLCJleHAiOjE2NzI0ODkxODYsIm5iZiI6MTY3MjQ4OTE4MSwiaWF0IjoxNjcyNDg5MTgxLCJqdGkiOiIwMUdOTTFaOFEzQkQ4ODFCUlA3UEZRMUoxVCJ9.UE9DrgJY8oz7FzQ2izFBp6NKEaDYOLON7c9Xxe9B4D4"
}
```
And following is the claims inside the token:
```json
{
  "user_id": "00000000000000000000000000",
  "iss": "login_jwt", // the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
  "exp": 1645688551, // the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
  "nbf": 1645688546, // the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
  "iat": 1645688546, // the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
  "jti": "01FWNAWRS6TJ2QXDSDBDEMCZD8" // the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
}
```

## HTTP Cookies

The endpoint will return the token not only in response body but also in cookies.  
In response body: `{"token":"foo"}`.  
In cookie: `kg_jwt=foo"`   
HTTP cookie has Secure, HTTPOnly and SameSite flags. The cookie is set for 1 year.

When browser makes an API request it should pass a token in `Authorization` header or keep it in the cookies.   


**/api/auth/login** endpoint returns JWT token
in response body. For example,
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJvd25lcl9pZCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidXNlcl9pZCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwicm9sZSI6ImFwcHJvdmVyIiwic2NvcGVzIjpbImNyeXB0b19wYXltZW50cyIsImJ1eV9vcmRlcnMiLCJzZWxsX29yZGVycyIsImFwcHJvdmFscyJdLCJpc3MiOiJidXNpbmVzc19wb3J0YWwiLCJleHAiOjE2NDU2ODg1NTEsIm5iZiI6MTY0NTY4ODU0NiwiaWF0IjoxNjQ1Njg4NTQ2LCJqdGkiOiIwMUZXTkFXUlM2VEoyUVhEU0RCREVNQ1pEOCJ9.Mi_UaXWjoVylMrHjW_ncLT37LDw9c8S02Jy8h06MB0U"
}
```

For every request to protected resources you need to attach following things:

JWT, there are some options to pass JWT from `kg_jwt` cookies or from login response body to backend:
1. Via `Authorization=Bearer <jwt_token>` headers
2. Or keep it in the `kg_jwt` cookies

## JSON Web Token Authentication

**GET /api/auth/validate**
It validates the jwt token in the header.   
If the jwt is not exists or invalid then it will return 401 Unauthorized

If the `Bearer` token (jwt token) in the header or in the cookies is exist and valid then it will return a 200 response.   
1. JWT in Header
```shell
$ curl -X GET -H "Authorization: Bearer <jwt_token>" http://localhost/v1/auth/validate
```
2. JWT in Cookies
```shell
$ curl -X GET -H "Cookie: kg_jwt=<jwt_token>" http://localhost/v1/auth/validate
```

We need to call this endpoint before calling login endpoint

**POST /api/auth/login**

Here we check email/password and return `bearer` token.

Attributes:

- **email** Email address
- **password**

```shell
$ curl -X POST -H "Content-Type: application/json" \
    -d '{"email":"user@email.com","password":"123"}' \
    http://localhost/api/auth/login
```

response body
```json
{
    "token": "<header.payload.signature>",
}
```

To access protected API urls you must include the `Authorization: Bearer <jwt_token>` header or
`kg_jwt` cookie.
1. JWT in Header
```shell
$ curl -H "Authorization: Bearer <jwt_token>" http://localhost/users
```
2. JWT in Cookies
```shell
$ curl -X GET -H "kg_jwt=<jwt_token>" http://localhost/users
```

## JSON Web Token Validation

Some of our API services delegate the responsibility of confirming that
a user is logged in to **Login App** authentication service.
This means that a service will pass a JWT received from the user to
the authentication service, and wait for a confirmation that the JWT is valid
before returning protected resources to the user.

## JSON Web Token Refresh

**POST /api/auth/refresh**

It refreshes `bearer` token. If it's available and non-expired bearer token,
it will return refreshed bearer token with status code `201 Created`.
```shell
$ curl -X POST -H "Cookie: kg_jwt=<jwt_token>" \
    -H "Authorization: Bearer <jwt_token>" \
    http://localhost/api/auth/refresh
```

## JSON Web Token Revoking

**POST /api/auth/logout**

It revokes `bearer` token so it can't be used anymore to access API resources.
```shell
$ curl -X POST -H "Cookie: kg_jwt=<jwt_token>" \
    -H "Authorization: Bearer <jwt_token>" \
    http://localhost/api/auth/logout
```