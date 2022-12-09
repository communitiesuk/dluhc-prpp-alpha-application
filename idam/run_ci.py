#!/usr/bin/python3

import subprocess
import boto3
import urllib.request
import json
import configparser
from urllib import request
import time
import os
import sys
from argparse import ArgumentParser
import base64

SONAR_KEY = os.environ.get("SONAR_KEY", "194c8ae3bb154712eb13de26a6d2bef0580322b8")
CODECOMMIT_PULL_REQUEST_ID = os.environ.get("CODECOMMIT_PULL_REQUEST_ID")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")
ENABLED_CHECKS = ["flake8", "pytest"]


def run_ci():
    result = {"status": "success", "tools": {}}

    try:
        subprocess.check_call(
            "snyk test --file=requirements.txt --package-manager=pip --severity-threshold=critical --exclude-base-image-vulns",
            shell=True,
        )
        result["tools"]["snyk"] = "success"
    except Exception as e:
        print("snyk failed")
        result["tools"]["snyk"] = "failed"

    try:
        subprocess.check_call(
            "flake8 --ignore=E402,E501,E712,W503,E203,I002,F523 --exclude=venv/ src/ tests/",
            shell=True,
        )
        result["tools"]["flake8"] = "success"
    except Exception as e:
        print("flake8 failed")
        result["tools"]["flake8"] = "failed"

    try:
        subprocess.check_call("black --check --exclude=venv/ src/ tests/", shell=True)
        result["tools"]["black"] = "success"
    except Exception as e:
        print("black failed")
        result["tools"]["black"] = "failed"

    try:
        subprocess.check_call(
            "pytest -rf -c tests/pytest.ini --cov=src --cov-context=test --disable-warnings",
            shell=True,
        )
        result["tools"]["pytest"] = "success"
    except Exception as e:
        print("pytest failed")
        result["tools"]["pytest"] = "failed"

    try:
        subprocess.check_call("bandit -r src -x venv", shell=True)
        result["tools"]["bandit"] = "success"
    except Exception as e:
        print("bandit failed")
        result["tools"]["bandit"] = "failed"

    # subprocess.check_call("coverage xml", shell=True)

    for check, value in result["tools"].items():
        if check in ENABLED_CHECKS and value == "failed":
            result["status"] = "failed"

    return result


def run_sonar():
    try:
        print("Running sonarqube scanner...")
        subprocess.check_call(
            "sonar-scanner -Dsonar.host.url=https://sonar.ncscdev.co.uk -Dsonar.login={}".format(
                SONAR_KEY
            ),
            shell=True,
        )
    except Exception as e:
        print("Failed to run sonar. {}".format(e))


def get_sonar_properties():
    with open("sonar-project.properties", "r") as f:
        config_string = "[dummy_section]\n" + f.read()

    config = configparser.ConfigParser()
    config.read_string(config_string)

    project_key = config["dummy_section"]["sonar.projectKey"]
    password = config["dummy_section"]["sonar.password"]

    return project_key, password


def get_project_status(project_key, login, password):
    failed_checks = []
    url = "https://sonar.ncscdev.co.uk/api/qualitygates/project_status?projectKey={}".format(
        project_key
    )
    login_and_password = login + ":" + password

    basic_auth = base64.b64encode(login_and_password.encode()).decode("ascii")

    headers = {"Authorization": "Basic {}".format(basic_auth)}

    req = urllib.request.Request(url, headers=headers)

    with urllib.request.urlopen(req) as response:
        response_body = response.read()

    data = json.loads(response_body.decode("utf-8"))

    conditions = data["projectStatus"]["conditions"]
    project_status = data["projectStatus"]["status"]

    for key in conditions:
        if key["status"] == "ERROR":
            failed_checks.append("metricKey: " + key["metricKey"])
            failed_checks.append("errorThreshold: " + key["errorThreshold"])
            failed_checks.append("actualValue: " + key["actualValue"])

    return project_status, failed_checks


# run_ci()


def get_codecommit_pr(pr_id):
    client = boto3.client("codecommit")

    response = client.get_pull_request(
        pullRequestId=str(pr_id),
    )

    return response


def post_to_slack(
    slack_channel, result, project_key, author, repositoryName, sourceReference
):

    color = None
    pretext = None
    text = None
    failed_checks = []

    for check, value in result["tools"].items():
        if value == "failed":
            failed_checks.append(check)

    if result["status"] == "success":
        color = "#d4edda"
        pretext = "CI has completed successfully for project {}".format(repositoryName)
        text = "PR ID: {PR_ID} \nAuthor : {author} \nRepository: {repositoryName} \nSource Reference: {sourceReference} \nFailed checks: {failed_checks}\nSonarqube report: https://sonar.ncscdev.co.uk/dashboard?id={project_key}".format(
            author=author,
            failed_checks=failed_checks,
            project_key=project_key,
            PR_ID=CODECOMMIT_PULL_REQUEST_ID,
            repositoryName=repositoryName,
            sourceReference=sourceReference,
        )
    else:
        color = "#FF0000"
        pretext = "CI has failed for project {}".format(repositoryName)
        text = "PR ID: {PR_ID} \nAuthor : {author} \nRepository: {repositoryName} \nSource Reference: {sourceReference} \nFailed checks: {failed_checks}\nSonarqube report: https://sonar.ncscdev.co.uk/dashboard?id={project_key}".format(
            author=author,
            failed_checks=failed_checks,
            project_key=project_key,
            PR_ID=CODECOMMIT_PULL_REQUEST_ID,
            repositoryName=repositoryName,
            sourceReference=sourceReference,
        )

    slack_data = {
        "attachments": [
            {
                "fallback": "Required plain-text summary of the attachment.",
                "color": color,
                "pretext": pretext,
                "title": "CI report:",
                "text": text,
                "footer": "CI",
                "ts": "{}".format(time.time()),
            }
        ]
    }

    try:
        slack_webhook_url = slack_channel
        json_data = json.dumps(slack_data)
        req = request.Request(
            slack_webhook_url,
            data=json_data.encode("ascii"),
            headers={"Content-Type": "application/json"},
        )
        resp = request.urlopen(req)
        return resp
    except Exception as em:
        print("EXCEPTION: " + str(em))


def main():

    ci_run = run_ci()
    # run_sonar() Turn sonar off for now.  Let's get the basics working first.

    # pr = get_codecommit_pr(CODECOMMIT_PULL_REQUEST_ID)

    # author = pr['pullRequest']['authorArn'].split('/')[1]
    # repositoryName = pr['pullRequest']['pullRequestTargets'][0]['repositoryName']
    # sourceReference = pr['pullRequest']['pullRequestTargets'][0]['sourceReference']

    # project_key, password = get_sonar_properties()
    # gate_status, failed_gates = get_project_status(project_key, SONAR_KEY, password)

    # post_to_slack(SLACK_CHANNEL, ci_run, project_key, author, repositoryName, sourceReference)

    if ci_run["status"] == "failed":
        print("test failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
