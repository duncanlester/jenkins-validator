FROM jenkins/jenkins:lts
USER root
RUN apt-get update && apt-get install -y docker.io
RUN groupadd -g 999 docker && usermod -aG docker jenkins
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs
USER jenkins
