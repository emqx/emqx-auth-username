emqx_auth_username
==================

Authentication with Username and Password

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

EMQ X-Men Team.

