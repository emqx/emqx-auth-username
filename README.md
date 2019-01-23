emqx_auth_username
==================

EMQ X Authentication with Username and Password

Build
-----

```
make && make tests
```

Configuration
-------------

etc/emqx_auth_username.conf:

```
##auth.user.$N.username = admin
##auth.user.$N.password = public

## Password hash.
##
## Value: plain | md5 | sha | sha256 | bcrypt
auth.user.password_hash = md5
```

Load the Plugin
---------------

```
./bin/emqx_ctl plugins load emqx_auth_username
```

License
-------

Apache License Version 2.0

Author
------

EMQ X Team.

