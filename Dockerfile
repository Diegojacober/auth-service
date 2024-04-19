FROM maven:3.6.3-openjdk-17-slim as BUILD
# Set the working directory in the container
ENV APP_HOME=/usr/app/
WORKDIR $APP_HOME

# Copy the pom.xml and the project files to the container
COPY pom.xml $APP_HOME
COPY src $APP_HOME/src
# COPY settings.xml /root/.m2/settings.xml
# Build the application using Maven
RUN mvn clean package

FROM openjdk:21-slim
ENV APP_HOME=/usr/app/

WORKDIR $APP_HOME
COPY --from=BUILD $APP_HOME/target/app_auth_keycloak-0.0.1-SNAPSHOT.jar ./app_auth_keycloak-0.0.1-SNAPSHOT.jar
EXPOSE 8083

# Set the command to run the application
CMD ["java", "-jar", "app_auth_keycloak-0.0.1-SNAPSHOT.jar"]