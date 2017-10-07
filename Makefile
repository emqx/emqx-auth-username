PROJECT = emqx_auth_username
PROJECT_DESCRIPTION = EMQ X Authentication with Username/Password
PROJECT_VERSION = 2.4

BUILD_DEPS = emqx cuttlefish
dep_emqx = git https://github.com/emqtt/emqttd X
dep_cuttlefish = git https://github.com/emqtt/cuttlefish

NO_AUTOPATCH = cuttlefish

ERLC_OPTS += +debug_info
ERLC_OPTS += +'{parse_transform, lager_transform}'

TEST_ERLC_OPTS += +debug_info

TEST_ERLC_OPTS += +'{parse_transform, lager_transform}'

COVER = true

include erlang.mk

app.config::
	./deps/cuttlefish/cuttlefish -l info -e etc/ -c etc/emqx_auth_username.conf -i priv/emqx_auth_username.schema -d data
