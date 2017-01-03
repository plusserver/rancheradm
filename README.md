rancheradm - a simple rancher server administration utility. Supports some tasks that rancher-cli
does not provide. Can be used for supporting automated rancher setups.

Requires Rancher 1.2.0 or later.

```
Usage: rancheradm [options] command...

  rancheradm token              -- create admin token
  rancheradm localauth (on|off) -- check, enable or disable local authentication
                                   (enabling will use adminuser/adminpassword)
  rancheradm get SETTING        -- get setting
  rancheradm set SETTING VALUE  -- set setting to value
  rancheradm environments       -- list environments
  rancheradm registration ENV   -- get registration url for environment ENV (default: Default)
  rancheradm envapikey ENV      -- create environment api key for ENV (default: Default)
```

Most commands require authentication by one of admin user/password, admin access/secret key
or admin jwt token. Those and the RANCHER_URL can be set in the environment.

To get the registration URL for an enviroment, you need to set the api.host first, for example

```
rancheradm set api.host $RANCHER_URL
```
