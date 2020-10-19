FROM rust:latest AS build
ADD . /app
WORKDIR /app
RUN cargo build --release
ENTRYPOINT ["/app/target/release/jwt"]
FROM debian:buster-slim
COPY --from=build /app/target/release/jwt /home/jwt
ENTRYPOINT ["/home/jwt"]