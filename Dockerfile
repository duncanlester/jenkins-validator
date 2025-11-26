FROM jenkins/jenkins:lts

USER root
COPY plugins/*.jpi /var/jenkins_home/plugins/
RUN chown -R jenkins:jenkins /var/jenkins_home/plugins/
USER jenkins