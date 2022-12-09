# CyberFirst IDAM Microservice
This repository contains the IDAM backend microservice used to manage CyberFirst users.

# Rest API
The interface for this service is specified in the `interface_spec.yml` file.  Import this file into [Swagger](https://editor.swagger.io/) or [Postman](https://www.postman.com/) to view and interact with the RESTful API for this service.

# Deployment Guide
## Deploy to INT
### 1. Set environment variables in `.env.int`
`.env.int`:
```
JWT_SECRET_KEY="add-your-jwt-secret-here"
USER_POOL_ID="add-your-user-pool-id"
CLIENT_ID="add-your-client-id-here"
CLIENT_ID_NO_SECRET="add-your-client-id-here"
CLIENT_SECRET="add-your-client-secret-here"
AWS_ACCESS_KEY_ID="add-your-aws-access-key-here"
AWS_SECRET_ACCESS_KEY="add-your-aws-secret-key-here"
AWS_REGION_NAME="set-aws-region-name"
COGNITO_AUTH_DOMAIN="set-cognito-auth-domain"
IDAM_UI_BASE_URL="set-idam-ui-base-url"
PLATFORM_CLIENT_ID="add-your-platform-client-id-here"
PLATFORM_CLIENT_SECRET="add-your-platform-client-secret"
PERF_TEST="set-performance-test-mode"
```
### 2. Build Docker Image
```
$ make build-int
```
### 3. Start Docker Container
```
$ make start-int
```

# Local Set Up For Development
## Running the service on local machine
### 1. Set environment variables in `.env.dev`
`.env.dev`:
```
JWT_SECRET_KEY="add-your-jwt-secret-here"
USER_POOL_ID="add-your-user-pool-id"
CLIENT_ID="add-your-client-id-here"
CLIENT_ID_NO_SECRET="add-your-client-id-here"
CLIENT_SECRET="add-your-client-secret-here"
AWS_ACCESS_KEY_ID="add-your-aws-access-key-here"
AWS_SECRET_ACCESS_KEY="add-your-aws-secret-key-here"
AWS_REGION_NAME="set-aws-region-name"
COGNITO_AUTH_DOMAIN="set-cognito-auth-domain"
IDAM_UI_BASE_URL="set-idam-ui-base-url"
PLATFORM_CLIENT_ID="add-your-platform-client-id-here"
PLATFORM_CLIENT_SECRET="add-your-platform-client-secret"
PERF_TEST="set-performance-test-mode"
```
### 2. Build docker image
```
$ make build
```

### 3. Run the docker image
```
$ make start
```
__note:__ you can check that the service is reachable with `curl http://0.0.0:1060/ping`

## Attaching to the container
*From the command line:*
```
$ docker exec -t <container-id> sh
```
*From `vscode`:*
Install the docker vscode extension, under the containers section right click the runing container and select `Attach Shell`.

Now you can run the tests as follows:
```
$ make test
```
Run the coverage:
```
$ make coverage
```

## Environment Variables
See the `.env_example` file for the environment configuration variables.  Those variables need to be added to a `.env` file to be created at deployment stage.

### `CLIENT_ID`
#### Type: string

#### Description:
This is a string id created in AWS used by AWS to identify this application.

### `CLIENT_SECRET`
#### Type: string

#### Description:
This is a string id created in AWS used by AWS to authenticate this application.

### `AWS_ACCESS_KEY_ID`
#### Type: string

#### Description:
This is a string id created in AWS used by AWS to authenticate this application to use the boto3 SDK.

### `AWS_SECRET_ACCESS_KEY`
#### Type: string

#### Description:
This is a string password created in AWS used by AWS to authorise this application to use the boto3 SDK.

### `AWS_REGION_NAME`
#### Type: string

#### Description:
This is a string id created in AWS used by AWS to identify the AWS service region.

### `COGNITO_AUTH_DOMAIN`
#### Type: string

#### Description:
This is a string id created in AWS used by AWS to identify the AWS service region.

### `IDAM_UI_BASE_URL`
#### Type: string

#### Description:
The base URL of where IDAM UI is located at.

### `PLATFORM_CLIENT_ID`
#### Type: string

#### Description:
This is a string id for the idam platform. Requires an App Client to be created within the Cognito User Pool.

### `PLATFORM_CLIENT_SECRET`
#### Type: string

#### Description:
This is a string password created in AWS used by AWS to identify the idam platform. Requires an App Client to be created within the Cognito User Pool.

### `PERF_TEST`
#### Type: bool

#### Description:
This is a boolean flag that can be used to enable/ disable MFA for all users. Used for performance testing of the application.

### `JWT_SECRET_KEY`
#### Type: string

#### Description:
This is a string key used for encryption of the API. Within the scripts directory setup.py can be run to create an API KEY for usage of the IDAM API.

### `IDAM_API_KEY`
#### Type: string

#### Description:
This is a string key used for encryption of the API. Within the scripts directory setup.py can be run to create an API KEY for usage of the IDAM API.

### `USER_POOL_ID`
#### Type: string

#### Description:
String to represent the Cognito User Pool (Deprecated). With the use of the User Pool Map we can handle multiple Cognito User Pools.

## Cognito Setup Notes
#### App Integration `Domain name`
For confirmation emails to work, you need to make sure that a domain name has been setup under `App integration`.

#### Custom Domain
So that we can use our own custom UI, the `Custom Domain` settings will need to be configured in the platform as per the [AWS docs](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-add-custom-domain.html).

#### Email Verification & Forgot / Reset Password
For verification via email to a custom application, AWS cognito requires Lambda overrides via Triggers. There are several Triggers available including, Pre-Sign Up, Post-Sign Up, Post Authentication, Post Confirmation...

By setting a AWS Lambda to be triggered you can customise workflow and user experience. 

Currently this IDAM service is using the Custom Message trigger assigned to `VerifyRedirect-Lambda` to automatically grab a verification code or reset password code and pass this variable to the IDAM frontend as url params when clicked in an email.

## Docker Container
`docker-compose --env-file ./.env.dev build idam`
`docker-compose --env-file ./.env.dev up idam`


## User Pool Maps
- IDAM Requires a user pool map for each application (Authoring / Competition)
- Each application requires a Cognito User Pool with 3 App Clients
    - IDAM
        *idam_client*
    - IDAM (with no secret key)
        *idam_no_secret_client_id*
    - Competition / Authoring
        *mfa_client* / *non2fa_client*
- Pool ID should be the multifactor authentication pool
- Pool type depends on which competition is going to be run with 2 options available. MFA is for Competitions that have over 18 competitions that will be using MFA. Guardian is for Competitions with under 18 users that will not use 2FA.
- Competition Name: The Competition title that is shown in the header of IDAM & Competition.
- Theme type: The theme that you would like to use. 1: Authoring, 2: Careers, 3: Learning
- Callback Urls: The allowed redirect URLS that IDAM can redirect back to.

### Example User Pool Map
```
{
    "idam_client_id": "2sj8bqo6g8ps8aimokve93hq0c",
    "idam_client_secret": "190rf1kkgkj28kgst9toobh05m0jm8ptfneugl3s84779n1h7f27",
    "idam_no_secret_client_id": "535fsdvkscadtslvsk2m4bm3gt",
    "mfa_client_id": "g81a0855rso96o9plmvqnsf5k",
    "mfa_client_secret": "d071j2v84b0jovt3t201mmpneh413ol2cl1rhcci49qmvkq9mbm",
    "non2fa_client_id": "6ms6mt8mua1nv6nr1vqh2gbs5k",
    "non2fa_client_secret": "e9fdgmb10vbnlq18ugh45k5ki0bu84ub1kp70v7l06hk5plnk59",
    "pool_id": "eu-west-1_4g7CDXiMf",
    "pool_type": "GUARDIAN",
    "u18_pool_id": "eu-west-1_ADX75mUId",
    "comp_name": "Comp",
    "pool_name": "cf-competition-comp-c-mfa-int",
    "theme_type": 2,
    "callback_urls": [
        "http://localhost:1050/idam-redirect", "https://competition.int.cyberfirst.ncscdev.co.uk/idam-redirect"
    ]
}
```
