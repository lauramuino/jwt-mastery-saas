Experimenting with JWT and FastApi

Endpoints:
/register   (creates new user with hashed password in db)
/login      (authenticates and returns a jwt access and refresh tokens expiring in 15min and 7days each)
/free-content
/premium-content
/admin     (endpoints to test token, free, premium and admin accesses)

/refresh   (refresh access token)
/logout    (revokes access and refresh token)

Access control based on roles(RBAC).
Added postgresdb for persistance.
Added redis cache for faster token handling

Build with docker-compose up --build

Documentation at /docs