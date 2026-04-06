# ============================================================
# Multi-Stage Dockerfile — GaaS Auth Service
# ============================================================
#
# PURPOSE:
#   Builds a minimal, secure Docker image for the Spring Boot auth service.
#
# WHY MULTI-STAGE?
#   A single-stage build that compiles and runs from the same image would
#   include the entire JDK (~650 MB) in the final image. With multi-stage:
#     Stage 1 (builder): has the full JDK to compile Java and run Maven
#     Stage 2 (runtime): has only the JRE needed to run the compiled JAR
#   The final image is ~250 MB — a 60% reduction. Smaller images mean:
#     - Faster pull times in CI and Kubernetes
#     - Smaller attack surface (no compiler, no build tools in production)
#     - Less storage cost in your container registry
#
# LAYER CACHING STRATEGY:
#   Docker caches each RUN instruction as a layer. When you rebuild:
#     - If only Java source files changed → Maven deps layer is REUSED (fast)
#     - If pom.xml changed → deps layer is INVALIDATED and re-downloaded
#   We separate "download deps" from "compile" so source changes don't
#   trigger a full Maven dependency download.
#
# SECURITY HARDENING:
#   - Non-root user (appuser) — if the app is compromised, the attacker
#     has no root privileges in the container
#   - JRE runtime (not JDK) — no compiler or javac in the final image
#   - eclipse-temurin is the official AdoptOpenJDK distribution, well-maintained
#     and regularly patched for CVEs
# ============================================================

# ============================================================
# STAGE 1: Build Stage
# Compiles the Maven project and produces the fat JAR.
# This stage is NOT included in the final image.
# ============================================================
FROM eclipse-temurin:21-jdk-jammy AS builder

# /workspace is our build directory inside the container.
# All subsequent COPY and RUN commands operate relative to this directory.
WORKDIR /workspace

# Copy the Maven POM file first — BEFORE copying source code.
# WHY: Docker checks if this layer has changed. If pom.xml hasn't changed
# since the last build, the dependency download step below is skipped entirely
# (served from cache), even if source files have changed.
COPY pom.xml .

# Download all Maven dependencies into the local repository cache (/root/.m2).
# --mount=type=cache keeps /root/.m2 across builds in the same Docker BuildKit session,
# so repeated builds don't re-download the internet even when the cache layer is invalidated.
# -q suppresses verbose Maven output, keeping CI logs clean.
RUN --mount=type=cache,target=/root/.m2 \
    mvn dependency:go-offline -q

# Now copy all source files. This layer is invalidated when ANY source file changes,
# but since dependencies are already cached above, only the compile step re-runs.
COPY src ./src

# Compile and package the application into a single executable fat JAR.
# -DskipTests: unit tests are run in a separate CI job, not during image build.
# The output is: target/auth-service-1.0.0.jar
RUN --mount=type=cache,target=/root/.m2 \
    mvn clean package -DskipTests -q

# ============================================================
# STAGE 2: Runtime Stage
# Copies only the compiled JAR from Stage 1 — no build tools included.
# This is the image that gets pushed to the registry and deployed to K8s.
# ============================================================
FROM eclipse-temurin:21-jre-jammy AS runtime

# /app is the working directory inside the runtime container.
WORKDIR /app

# Create a system group and user with no home directory and no login shell.
# Running as a non-root user is a CIS Docker benchmark requirement and prevents
# a compromised application from modifying system files or escalating privileges.
RUN groupadd --system appgroup && useradd --system --gid appgroup appuser

# Switch to the non-root user BEFORE copying files.
# Files copied after USER appuser are owned by appuser, not root.
USER appuser

# Copy only the compiled JAR from the builder stage.
# The wildcard handles the version suffix (auth-service-1.0.0.jar → app.jar).
# Nothing else from the builder stage (source code, Maven cache, JDK) is included.
COPY --from=builder /workspace/target/auth-service-*.jar app.jar

# Inform Docker and Kubernetes that this container listens on port 8081.
# EXPOSE is documentation — it does NOT actually open the port.
# The actual port binding happens in the Kubernetes Service manifest or `docker run -p`.
EXPOSE 8081

# Kubernetes uses HEALTHCHECK to determine when the container is ready to receive traffic.
# The Spring Boot Actuator /actuator/health endpoint returns:
#   {"status": "UP"} with HTTP 200 when healthy
#   {"status": "DOWN"} with HTTP 503 when unhealthy
# --start-period=30s: give the JVM 30 seconds to start before health checks begin.
#   Without this, Kubernetes may kill the container before Spring Boot finishes loading.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8081/actuator/health || exit 1

# The ENTRYPOINT command runs when the container starts.
# Using exec form (JSON array) instead of shell form ("java -jar app.jar") ensures
# the Java process receives OS signals (SIGTERM for graceful shutdown) directly,
# rather than having them intercepted by a shell wrapper.
ENTRYPOINT ["java", "-jar", "app.jar"]
