# Dockerfile for meds_backend.js
FROM node:18-alpine

WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
# Using --omit=dev which is preferred over --production for newer npm versions
RUN npm install --omit=dev --ignore-scripts

# Copy backend code
COPY meds_backend.js .

# Expose the port the app runs on (e.g., 3001)
EXPOSE 3001

# Command to run the application
CMD [ "node", "meds_backend.js" ]
