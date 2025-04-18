# Dockerfile for meds_backend.js
FROM node:18-alpine

WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install build tools needed for native modules like bcrypt, run npm install, then remove build tools
# Using apk add --virtual creates a temporary group we can easily remove later
RUN apk add --no-cache --virtual .build-deps python3 make g++ && \
    npm install --omit=dev && \
    apk del .build-deps

# Copy backend code AFTER npm install to leverage Docker cache better
COPY meds_backend.js .

# Expose the port the app runs on (e.g., 3001)
EXPOSE 3001

# Command to run the application
CMD [ "node", "meds_backend.js" ]
