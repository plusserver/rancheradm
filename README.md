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

```
Options:

  -adminaccesskey string
    	rancher admin access key (env RANCHER_ADMIN_ACCESS_KEY)
  -adminpassword string
    	rancher admin password (env RANCHER_ADMIN_PASSWORD)
  -adminsecretkey string
    	rancher admin secret key (env RANCHER_ADMIN_SECRET_KEY)
  -admintoken string
    	rancher admin jwt token (env RANCHER_ADMIN_TOKEN)
  -adminuser string
    	rancher admin user (env RANCHER_ADMIN_USER)
  -debug
    	debug mode
  -url string
    	rancher url (env RANCHER_URL) (default "http://localhost:8080/")
  -waitretry int
    	wait/retry until rancher is up (in seconds)
```

To get the registration URL for an enviroment, you need to set the api.host first, for example

```
rancheradm set api.host $RANCHER_URL
```
