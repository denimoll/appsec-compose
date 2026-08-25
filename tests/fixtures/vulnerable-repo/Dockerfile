# Deliberately bad: exercises Trivy config, Checkov and Hadolint at once.
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
EXPOSE 22
COPY . /app
CMD ["/app/run.sh"]
