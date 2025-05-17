FROM eclipse-temurin:17-jdk-jammy as builder
WORKDIR /app
COPY build.gradle settings.gradle gradlew /app/
COPY gradle /app/gradle
RUN ./gradlew build -x test --no-daemon || return 0
COPY . /app
RUN ./gradlew bootJar -x test --no-daemon
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar Gradle_Docker.jar
EXPOSE 9090sss
ENTRYPOINT ["java", "-jar", "OpenId_Connect.jar"]
