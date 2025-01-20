# simple-todo-app

# postgres docker
docker run -d \
  --name my_postgres_container \
  -e POSTGRES_USER=myuser \
  -e POSTGRES_PASSWORD=mypassword \
  -e POSTGRES_DB=mydatabase \
  -p 5432:5432 \
  postgres:latest

# how to run (without building)
go run main.go

# do not FORGET (run this in postgres, to support UUID)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

# things to consider:
- Separate each module
- Detailed models
