# Stage 1: Build the binary with rust
FROM rust:slim-buster as builder

WORKDIR /usr/src/rs_crypto_msg

# Copy the current directory contents into the container
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev  && rm -rf /var/lib/apt/lists/*

# Build our application
RUN cargo prisma migrate deploy
RUN cargo prisma generate 
RUN cargo build --release

# Stage 2: Setup runtime environment and copy binary from builder
FROM debian:buster-slim

# Install libssl
RUN apt-get update && apt-get install -y libssl1.1  && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage to the current stage
COPY --from=builder /usr/src/rs_crypto_msg/target/release/rs_crypto_msg /usr/local/bin

# Set our binary as the command to run when the container starts
CMD ["rs_crypto_msg"]