FROM maven:3.9.6-amazoncorretto-17 AS build

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

FROM amazoncorretto:17-alpine

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENV DISCORD_TOKEN=""
ENV DISCORD_GUILD_ID=""
ENV MCP_CLIENT_SECRET=""
ENV MCP_ADMIN_PASSWORD=""
ENV MCP_RSA_KEY=""

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
