# -------------------------------------------------------------------
# ETAPA 1: BUILD (Compilación)
# ¡Asegúrate de que 'AS build' esté aquí!
FROM eclipse-temurin:17-jdk AS build

# Establece el directorio de trabajo
WORKDIR /app

# Copia los archivos de Maven
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn/
COPY src ./src

# Compila el código, genera el JAR
#RUN ./mvnw clean package -DskipTests
RUN chmod +x mvnw && ./mvnw clean package -DskipTests

# -------------------------------------------------------------------

# ETAPA 2: RUN (Ejecución)
FROM eclipse-temurin:17-jdk

WORKDIR /app

# Copia el JAR generado desde la etapa con nombre 'build'
COPY --from=build /app/target/*.jar app.jar

# Define el puerto
EXPOSE 8081

ENV JAVA_OPTS=""

# Comando para iniciar la aplicación
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
