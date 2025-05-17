FROM eclipse-temurin:17-jdk-jammy as builder

WORKDIR /app

# Copy Gradle config files
COPY build.gradle settings.gradle gradlew /app/
COPY gradle /app/gradle

# Give execute permission to gradlew
RUN chmod +x gradlew

# Pre-build to download dependencies (optional but speeds up builds)
RUN ./gradlew build -x test --no-daemon || return 0

# Copy the rest of the source code
COPY . /app

# Build the bootJar
RUN ./gradlew bootJar -x test --no-daemon

FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

# Copy the jar from the builder stage
COPY --from=builder /app/build/libs/*.jar OpenId_Connect.jar

EXPOSE 9090

ENTRYPOINT ["java", "-jar", "OpenId_Connect.jar"]
