# syntax=docker/dockerfile:1

# ---- Build stage: compile and package the jar -------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

# Dependencies first, so editing source code doesn't re-download them.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -q package

# ---- Runtime stage: JRE only, non-root --------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /build/target/*.jar app.jar
USER app

EXPOSE 8080

# Size the heap from the container's memory limit instead of a fixed -Xmx.
# The image defaults to the prod profile, which refuses to start with development settings.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError" \
    SPRING_PROFILES_ACTIVE=prod

# /api/v1/health is exempt from rate limiting. busybox wget ships with the alpine image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
