# Use the official Python 3.9 image adapted for VS Code dev containers
FROM mcr.microsoft.com/vscode/devcontainers/python:3.9

# [Optional] Install any OS packages you need
RUN apt-get update && apt-get install -y curl

# Set the working directory
WORKDIR /workspace

# Switch to the non-root user (vscode) as defined in the base image
USER vscode
