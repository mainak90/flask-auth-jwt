# Flask-jwt-auth
Flask auth api that stores and retrieves user info from MongoDB and offers json-web-tokens for 
clients to authorize against

### Operations
Its pretty straightforward, just run using 
```
python app.py
```

### Environment parameters
The following parameters need to be set as environment variables before triggering the app
```
1) ROOT_LOGGER
2) PORT
3) ENV
DB params
4) MONGO_URI
JWT params
5) JWT_SECRET_KEY
6) JWT_BLACKLIST_ENABLED
7) JWT_BLACKLIST_TOKEN_CHECKS
8) JWT_ACCESS_TOKEN_EXPIRES
```

### Features and endpoints

#### Endpoints

| Endpoint | Verb | Description |
| :---: | :---: | :---: |
| /auth | `POST` | Authenticate an user that is already registered and return a JWT token |
| /register | `POST` | Register an user into the system, it adds user and salted password into MongoDB |
| /refresh | `POST` | Generate a new access token from the provided refresh token |
| /user | `GET, DELETE, PATCH` | Check if an user exists, delete the user or modify and existing user |
| /logout | `DELETE` | Logout the current user by invalidating the current user token |
| /revoke-refresh-token | `DELETE` | Revoke the users refresh token and return an OK response |
| /{path}/{file} | `GET` | Proxy endpoint for static contents served out of the 'public' document path | 

#### Features
1) Check for expired token.
2) Check for revoked token.
3) Check for blacklisted token.
4) Check for unauthorized/bad token.
5) For now no flask blueprints used, tests and code refactor to use views/models/blueprints on the way
6) Integrate json web signing and encryption/decryption of generated/consumed tokens(future feature) 