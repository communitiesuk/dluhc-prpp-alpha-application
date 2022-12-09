# GOV.UK Frontend Jinja Demo

Demo Flask app using [GOV.UK Frontend Jinja](https://github.com/LandRegistry/govuk-frontend-jinja) macros.

## Getting started

```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt ; pip3 install -r requirements_dev.txt
./build.sh
flask run
```


## Endpoints
```
/
/api/ping
/api/info
/home
/redirect
/gov-login
/cognito-login
/logout
/gov-logout
/cognito-register
/token
/reset-password
/dashboard
/address-select
/components*

```