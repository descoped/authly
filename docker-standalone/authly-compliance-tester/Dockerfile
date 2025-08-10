FROM nginx:alpine

# Copy the compliance tester files
COPY . /usr/share/nginx/html/

# Copy custom nginx configuration with proxy settings
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]