# Multi-stage build: compile in a JDK image, run in a lean JRE image
# This reduces the final image size from ~650MB to ~250MB by omitting
# the compiler toolchain from the runtime image.

# Stage 1: Build
FROM eclipse-temurin:21-jdk-jammy AS builder
WORKDIR /workspace

COPY pom.xml .
# Download dependencies separately to leverage Docker layer caching.
# If only source files change, Maven dependencies are NOT re-downloaded.
RUN --mount=type=cache,target=/root/.m2 \
    mvn dependency:go-offline -q

COPY src ./src
RUN --mount=type=cache,target=/root/.m2 \
    mvn clean package -DskipTests -q

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-jammy AS runtime
WORKDIR /app

# Run as a non-root user (security hardening)
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser
USER appuser

COPY --from=builder /workspace/target/auth-service-*.jar app.jar

# Port 8081 (see application.properties for rationale)
EXPOSE 8081

# Spring Boot actuator health endpoint used by K8s probes
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
