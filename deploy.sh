#!/usr/bin/env bash

CONTAINER_NAME=greenlight-v2
CONTAINER_PATH=/usr/src/app

#Initial commands that are installing openid_connect library to docker gems
#Uncomment for first use
docker cp openid_connect_gem $CONTAINER_NAME:$CONTAINER_PATH/openid_connect_gem
docker exec -it $CONTAINER_NAME bash -c "cat openid_connect_gem >> Gemfile"
docker exec -it $CONTAINER_NAME bundle install --no-deployment
docker exec -it $CONTAINER_NAME gem install openid_connect

docker cp app/controllers/sessions_controller.rb $CONTAINER_NAME:$CONTAINER_PATH/app/controllers/sessions_controller.rb
docker cp app/helpers/application_helper.rb $CONTAINER_NAME:$CONTAINER_PATH/app/helpers/application_helper.rb
docker cp app/models/user.rb $CONTAINER_NAME:$CONTAINER_PATH/app/models/user.rb
docker cp app/views/sessions/signin.html.erb $CONTAINER_NAME:$CONTAINER_PATH/app/views/sessions/signin.html.erb
docker cp config/locales/en.yml $CONTAINER_NAME:$CONTAINER_PATH/config/locales/en.yml
docker cp config/routes.rb $CONTAINER_NAME:$CONTAINER_PATH/config/routes.rb
#docker cp production.rb $CONTAINER_NAME:$CONTAINER_PATH/config/environments/production.rb