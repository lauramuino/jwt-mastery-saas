Experimenting with JWT and FastApi

Endpoints:
/register (creates new user with hashed password in db)
/login  (authenticates and returns a jwt token expiring in 30min)
/free-content
/premium-content
/admin           (endpoints to test token, free, premium and admin accesses)

Access control based on roles(RBAC).
Added postgresdb for persistance.

Build with docker-compose up --build

Documentation at /docs