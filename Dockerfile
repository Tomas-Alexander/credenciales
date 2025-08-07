FROM nginx:alpine
COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./farmer /usr/share/nginx/html/farmer
