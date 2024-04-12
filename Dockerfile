FROM maven:3.6.3-openjdk-17-slim as BUILD
# Set the working directory in the container
WORKDIR /app
# Copy the pom.xml and the project files to the container
COPY pom.xml .
COPY src ./src
# Build the application using Maven
RUN mvn clean package -DskipTests

FROM openjdk:21-slim
WORKDIR /app
COPY --from=BUILD /app/target/my-application.jar .
EXPOSE 8082

# Set the command to run the application
CMD ["java", "-jar", "my-application.jar"]