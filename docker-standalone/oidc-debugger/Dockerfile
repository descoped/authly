FROM node:lts-alpine

# Install git and patch to clone the repository and apply patches
RUN apk add --no-cache git patch

WORKDIR /usr/src/app

# Clone the OAuth2/OIDC debugger repository
RUN git clone --depth 1 https://github.com/rcbj/oauth2-oidc-debugger.git /usr/src/app

# Install dependencies for the client
WORKDIR /usr/src/app/client
RUN npm install && npm cache clean --force 
RUN npm install -g browserify

# Copy our custom Authly configuration
COPY authly-config.js /usr/src/app/client/src/env/authly.js

# Replace default endpoints with Authly endpoints in all relevant files
RUN for file in debugger.js debugger2.js introspection.js jwks.js userinfo.js; do \
        sed -i 's|"https://localhost/oauth2/authorization"|"http://localhost:8000/api/v1/oauth/authorize"|g' /usr/src/app/client/src/$file; \
        sed -i 's|"https://localhost/oauth2/token/introspect"|"http://localhost:8000/api/v1/oauth/introspect"|g' /usr/src/app/client/src/$file; \
        sed -i 's|"https://localhost/oauth2/token"|"http://localhost:8000/api/v1/oauth/token"|g' /usr/src/app/client/src/$file; \
        sed -i 's|"http://localhost:3000/callback"|"http://localhost:8083/callback"|g' /usr/src/app/client/src/$file; \
        sed -i 's|"https://localhost/oidc/.well-known"|"http://localhost:8000/.well-known/openid-configuration"|g' /usr/src/app/client/src/$file; \
        sed -i 's|"https://localhost/oidc/userinfo"|"http://localhost:8000/api/v1/userinfo"|g' /usr/src/app/client/src/$file; \
        sed -i 's|"https://localhost/oidc/.well-known/jwks"|"http://localhost:8000/.well-known/jwks.json"|g' /usr/src/app/client/src/$file; \
    done && \
    # Fix the introspection endpoint that got double-replaced
    for file in debugger.js debugger2.js introspection.js; do \
        sed -i 's|"http://localhost:8000/api/v1/oauth/token/introspect"|"http://localhost:8000/api/v1/oauth/introspect"|g' /usr/src/app/client/src/$file; \
    done

# Build the client with our Authly configuration
RUN browserify src/jwks.js -o public/js/jwks.js --debug --standalone jwks -t [ envify purge --CONFIG_FILE ./env/authly.js ]
RUN browserify src/debugger.js -o public/js/debugger.js --debug --standalone debug -t [ envify purge --CONFIG_FILE ./env/authly.js ]
RUN browserify src/token_detail.js -o public/js/token_detail.js --debug --standalone token_detail -t [ envify purge --CONFIG_FILE ./env/authly.js ]
RUN browserify src/debugger2.js -o public/js/debugger2.js --debug --standalone debugger2 -t [ envify purge --CONFIG_FILE ./env/authly.js ]
RUN browserify src/userinfo.js -o public/js/userinfo.js --debug --standalone userinfo -t [ envify purge --CONFIG_FILE ./env/authly.js ]
RUN browserify src/introspection.js -o public/js/introspection.js --debug --standalone introspection -t [ envify purge --CONFIG_FILE ./env/authly.js ]
RUN browserify src/logout.js -o public/js/logout.js --debug --standalone logout -t [ envify purge --CONFIG_FILE ./env/authly.js ]

# Install dependencies for the API server
WORKDIR /usr/src/app/api
RUN npm install && npm cache clean --force

# Copy startup script
WORKDIR /usr/src/app
COPY start.sh /usr/src/app/start.sh
RUN chmod +x /usr/src/app/start.sh

EXPOSE 3000 4000

CMD ["/usr/src/app/start.sh"]