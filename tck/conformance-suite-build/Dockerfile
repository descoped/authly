# Build conformance suite from source
FROM maven:3-eclipse-temurin-17 AS builder

WORKDIR /build

# Clone the official conformance suite
RUN git clone https://gitlab.com/openid/conformance-suite.git .

# Build the JAR
RUN mvn clean package -B -DskipTests=true

# Runtime stage
FROM eclipse-temurin:17-jre

COPY --from=builder /build/target/fapi-test-suite.jar /server/fapi-test-suite.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/server/fapi-test-suite.jar"]