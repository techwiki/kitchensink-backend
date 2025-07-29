# Kitchensink Backend

This project represents the backend component of the Kitchensink application, which has been extracted from the original monolithic Kitchensink project. This separation was done to create a more modular and scalable architecture, allowing the backend to serve multiple client applications (web, mobile, etc.) through a RESTful API.

## Overview

The Kitchensink Backend is built using Spring Boot and provides a robust API for the Kitchensink application. It includes features such as:

- RESTful API endpoints
- JWT-based authentication
- Role-based access control
- Member management
- MongoDB integration
- Public/Private key pair generation for password encryption
- Request ID tracking
- Comprehensive test coverage

## Prerequisites

Before running this project, ensure you have the following installed:

- Java Development Kit (JDK) 21 or higher (Required)
  ```bash
  # Check your Java version
  java -version
  
  # If you have multiple Java versions installed on macOS, you can switch versions using:
  # For Intel Macs
  export JAVA_HOME=$(/usr/libexec/java_home -v 21)
  # For M1/M2 Macs
  export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home
  ```
- Maven 3.8.x or higher
- MongoDB 6.0 or higher
- Git (for version control)

### Java Version Note

This project requires Java 21. If you see an error like this:
```
java.lang.UnsupportedClassVersionError: ... has been compiled by a more recent version of the Java Runtime (class file version 65.0), this version of the Java Runtime only recognizes class file versions up to 61.0
```
This means you're using an older version of Java (like Java 17). To fix this:
1. Install Java 21 from [Oracle](https://www.oracle.com/java/technologies/downloads/#java21) or using SDKMan
2. Set JAVA_HOME to point to Java 21
3. Ensure `java -version` shows version 21 before running the application

## Environment Setup

The application uses the following default configuration (defined in `application.properties`):

```properties
# MongoDB Configuration
spring.data.mongodb.host=localhost
spring.data.mongodb.port=27017
spring.data.mongodb.database=kitchensink

# Server Configuration
server.port=8080

# JWT Configuration
jwt.expiration=86400000

# Admin Configuration
admin.default.password=@dmin123
```

You can override these settings by:
1. Creating an `application-local.properties` file in `src/main/resources/`
2. Setting environment variables
3. Using command-line arguments

## Installation

1. Clone the repository (if not already done):
```bash
git clone <repository-url>
cd kitchensink-backend
```

2. Build the project:
```bash
mvn clean install
```

## Running the Application

### Development Mode

To run the application in development mode:

```bash
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`

### Production Build

To create a production build:

```bash
mvn clean package
```

To run the production build:

```bash
java -jar target/kitchensink-backend-1.0.0.jar
```

## Project Structure

- `/src/main/java/org/jboss/quickstarts/kitchensink`
  - `/config` - Application configuration
  - `/controller` - REST controllers
  - `/dto` - Data Transfer Objects
  - `/model` - Domain models
  - `/repository` - MongoDB repositories
  - `/security` - Security configuration and JWT handling
  - `/service` - Business logic

## Available Maven Commands

- `mvn clean install` - Clean and install the project
- `mvn test` - Run tests
- `mvn spring-boot:run` - Run the application
- `mvn package` - Create a deployable package

## Testing

The project includes both unit and integration tests. To run the tests:

```bash
# Run all tests
mvn test

# Run only unit tests
mvn test -Dtest=*Test

# Run only integration tests
mvn test -Dtest=*IT
```

## Security

The application implements several security measures:

1. JWT-based authentication
2. Password encryption using public/private key pairs
3. Role-based access control (ADMIN, USER roles)
4. Request ID tracking for better traceability

On first startup, the application automatically creates a default admin user with the following credentials:
- Email: admin@gmail.com
- Password: Value of `admin.default.password` from application.properties (default: @dmin123)
- Name: Admin User
- Phone: 1234567890

The default admin credentials are set in the properties file. Make sure to change these in production.
