# syntax=docker/dockerfile:1

# --------------- build -----------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

# pom.xml alone first: this layer stays cached until dependencies change.
COPY pom.xml .
RUN mvn -B dependency:go-offline

COPY src ./src
RUN mvn -B -DskipTests package

# --------------- runtime -----------
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

RUN addgroup -S spring && adduser -S spring -G spring
COPY --from=build --chown=spring:spring /build/target/*.jar app.jar
USER spring:spring

EXPOSE 8085
ENTRYPOINT ["java","-jar","app.jar"]