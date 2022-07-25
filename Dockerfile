FROM openjdk:8u212-jre-alpine3.9
ADD build/libs/signer-0.0.1-SNAPSHOT.jar .
ADD CA.crt .
ADD signer.key .
EXPOSE 12000
CMD java -jar signer-0.0.1-SNAPSHOT.jar