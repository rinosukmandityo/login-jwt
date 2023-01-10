## User

User is a user entity in Login app

### User Object

- `email` user email address

```json
{
  "email": "user@email.com"
}
```

### Get User by Email

Gets a user by email.

`GET /api/users/{email}`

Example request:

```shell
$ curl -X GET -H "Authorization: Bearer <jwt_token>" \
    http://api/users/user@email.com
```

we can put jwt token on the header or in the cookie

```shell
$ curl -X GET -H "Cookie: kg_jwt=<jwt_token>" \
    http://api/users/user@email.com
```

example response:

```200 OK```

```json
{
  "email": "user@email.com"
}
```

### Create User

Creates a new user

`POST /api/users`

example request:

```shell
$ curl -X POST -H "Content-Type: application/json" \
    -H "Authorization: Bearer <jwt_token>" \
    -d '{"email":"user@email.com"}' \
    http://localhost/api/users
```

we can put jwt token on the header or in the cookie

```shell
$ curl -X POST -H "Content-Type: application/json" \
    -H "Cookie: kg_jwt=<jwt_token>" \
    -d '{"email":"user@email.com"}' \
    http://localhost/api/users
```

example response:

```204 NO CONTENT```

### Update User

Updates user.

`PUT /api/users/{email}`

example request:

```shell
$ curl -X PUT -H "Content-Type: application/json" \
    -H "Authorization: Bearer <jwt_token>" \
    -d '{"email":"user_changed@email.com"}' \
    http://localhost/api/users/user@email.com
```

we can put jwt token on the header or in the cookie

```shell
$ curl -X PUT -H "Content-Type: application/json" \
    -H "Cookie: kg_jwt=<jwt_token>" \
    -d '{"email":"user_changed@email.com"}' \
    http://localhost/api/users/user@email.com
```

example response:

```200 OK```

### Delete User

Deletes a user by email.

`DELETE /api/users/{email}`

Example request:

```shell
$ curl -X DELETE -H "Authorization: Bearer <jwt_token>" \
    http://api/users/user@email.com
```

we can put jwt token on the header or in the cookie

```shell
$ curl -X DELETE -H "Cookie: kg_jwt=<jwt_token>" \
    http://api/users/user@email.com
```

example response:

```200 OK```
