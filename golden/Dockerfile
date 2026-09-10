FROM eclipse-temurin:21-jre

WORKDIR /app
COPY app/target/golden-app-1.0.0.jar /app/application.jar
COPY image-libs/target/image-libs/ /opt/manual-libs/

USER 10001
ENTRYPOINT ["java", "-jar", "/app/application.jar"]

