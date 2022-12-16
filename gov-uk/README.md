# GOV.UK Frontend Jinja Demo

Demo Flask app using [GOV.UK Frontend Jinja](https://github.com/LandRegistry/govuk-frontend-jinja) macros.

## Getting started

There is a Dockerfile available within the project or the project can be ran directly as a Flask App. The default port is 8000.

#### Flask App Setup

```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt ; pip3 install -r requirements_dev.txt
./build.sh
flask run
```

#### Docker App Setup
```
docker build -t prpp-app .
docker run prpp-app
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
/view-epc
/address-select

```

