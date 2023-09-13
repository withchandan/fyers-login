import requests
import pyotp
import hashlib
import os
import json
import boto3
import traceback
from datetime import datetime
from urllib.parse import parse_qs, urlparse
from boto3.dynamodb.conditions import Key

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
TABLE = "Trading"

APP_ID_TYPE = "2"  # Keep default as 2, It denotes web login
APP_TYPE = "100"
REDIRECT_URI = "https://google.com"

# API endpoints
BASE_URL = "https://api-t2.fyers.in/vagator/v2"
BASE_URL_2 = "https://api.fyers.in/api/v2"
URL_SEND_LOGIN_OTP = BASE_URL + "/send_login_otp"
URL_VERIFY_TOTP = BASE_URL + "/verify_otp"
URL_VERIFY_PIN = BASE_URL + "/verify_pin"
URL_TOKEN = BASE_URL_2 + "/token"
URL_VALIDATE_AUTH_CODE = BASE_URL_2 + "/validate-authcode"

SUCCESS = 1
ERROR = -1


dynamodb = boto3.resource(
    "dynamodb",
    region_name="ap-south-1",
)
tradingTable = dynamodb.Table(TABLE)


# Get all users from db
def getAllUsers():
    response = tradingTable.query(
        KeyConditionExpression=Key("pk").eq("client") & Key("sk").begins_with("FYERS")
    )
    return response["Items"]


# Save access token to dynamodb
def saveAccessToken(user, accessToken):
    date = datetime.now().isoformat()
    tradingTable.update_item(
        Key={"pk": user["pk"], "sk": user["sk"]},
        UpdateExpression="set accessToken = :accessToken, updatedAt = :updatedAt",
        ExpressionAttributeValues={":accessToken": accessToken, ":updatedAt": date},
        ReturnValues="UPDATED_NEW",
    )


# Send message on telegram
def sendTelegramMsg(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}

    requests.post(url, json=data).json()


def sendLoginOtp(fyersId, appId):
    try:
        payload = {"fy_id": fyersId, "app_id": appId}

        result_string = requests.post(url=URL_SEND_LOGIN_OTP, json=payload).json()
        if result_string.status_code != 200:
            return [ERROR, result_string.text]

        result = json.loads(result_string.text)
        request_key = result["request_key"]

        return [SUCCESS, request_key]

    except Exception as e:
        return [ERROR, e]


def generateTotp(secret):
    try:
        generated_totp = pyotp.TOTP(secret).now()
        return [SUCCESS, generated_totp]

    except Exception as e:
        return [ERROR, e]


def verifyTotp(requestKey, totp):
    try:
        payload = {"request_key": requestKey, "otp": totp}

        result_string = requests.post(url=URL_VERIFY_TOTP, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]

        result = json.loads(result_string.text)
        request_key = result["request_key"]

        return [SUCCESS, request_key]

    except Exception as e:
        return [ERROR, e]


def verifyPin(requestKey, pin):
    try:
        payload = {
            "request_key": requestKey,
            "identity_type": "pin",
            "identifier": pin,
        }

        result_string = requests.post(url=URL_VERIFY_PIN, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]

        result = json.loads(result_string.text)
        access_token = result["data"]["access_token"]

        return [SUCCESS, access_token]

    except Exception as e:
        return [ERROR, e]


def token(fyersId, appId, redirectUri, appType, accessToken):
    try:
        payload = {
            "fyers_id": fyersId,
            "app_id": appId,
            "redirect_uri": redirectUri,
            "appType": appType,
            "code_challenge": "",
            "state": "sample_state",
            "scope": "",
            "nonce": "",
            "response_type": "code",
            "create_cookie": True,
        }
        headers = {"Authorization": f"Bearer {accessToken}"}

        result_string = requests.post(url=URL_TOKEN, json=payload, headers=headers)

        if result_string.status_code != 308:
            return [ERROR, result_string.text]

        result = json.loads(result_string.text)
        url = result["Url"]
        auth_code = parse_qs(urlparse(url).query)["auth_code"][0]

        return [SUCCESS, auth_code]

    except Exception as e:
        return [ERROR, e]


def validateAuthcode(appIdHash, authCode):
    try:
        payload = {
            "grant_type": "authorization_code",
            "appIdHash": appIdHash,
            "code": authCode,
        }

        result_string = requests.post(url=URL_VALIDATE_AUTH_CODE, json=payload)
        if result_string.status_code != 200:
            return [ERROR, result_string.text]

        result = json.loads(result_string.text)
        access_token = result["access_token"]

        return [SUCCESS, access_token]

    except Exception as e:
        return [ERROR, e]


# Login into fyers and return access token
def login(user):
    name = user["name"]
    pin = user["pin"]
    userId = user["clientId"]
    apiKey = user["apiKey"]
    apiSecret = user["apiSecret"]
    totpKey = user["totpKey"]

    # Step 1 - Retrieve request_key from send_login_otp API
    send_otp_result = sendLoginOtp(fyersId=userId, appId=APP_ID_TYPE)
    if send_otp_result[0] != SUCCESS:
        print(f"Login failed at step1 for {name}", {send_otp_result[1]})
        raise Exception(f"Login failed at step1 for {name}")

    # Step 2 - Generate totp
    generate_totp_result = generateTotp(secret=totpKey)
    if generate_totp_result[0] != SUCCESS:
        print(f"Login failed at step2 for {name}", {generate_totp_result[1]})
        raise Exception(f"Login failed at step2 for {name}")

    # Step 3 - Verify totp and get request key from verify_otp API
    request_key = send_otp_result[1]
    totp = generate_totp_result[1]
    verify_totp_result = verifyTotp(requestKey=request_key, totp=totp)
    if verify_totp_result[0] != SUCCESS:
        print(f"Login failed at step3 for {name}", {verify_totp_result[1]})
        raise Exception(f"Login failed at step3 for {name}")

    # Step 4 - Verify pin and send back access token
    request_key_2 = verify_totp_result[1]
    verify_pin_result = verifyPin(requestKey=request_key_2, pin=pin)
    if verify_pin_result[0] != SUCCESS:
        print(f"Login failed at step4 for {name}", {verify_pin_result[1]})
        raise Exception(f"Login failed at step4 for {name}")

    # Step 5 - Get auth code for API V2 App from trade access token
    token_result = token(
        fyersId=userId,
        appId=apiKey,
        redirectUri=REDIRECT_URI,
        appType=APP_TYPE,
        accessToken=verify_pin_result[1],
    )
    if token_result[0] != SUCCESS:
        print(f"Login failed at step5 for {name}", {token_result[1]})
        raise Exception(f"Login failed at step5 for {name}")

    # Step 6 - Get API V2 access token from validating auth code
    h = hashlib.sha256(f"{apiKey}-{APP_TYPE}:{apiSecret}".encode("utf-8"))
    appIdHash = h.hexdigest()
    auth_code = token_result[1]
    validate_authcode_result = validateAuthcode(appIdHash=appIdHash, authCode=auth_code)
    if token_result[0] != SUCCESS:
        print(f"Login failed at step6 for {name}", {validate_authcode_result[1]})
        raise Exception(f"Login failed at step6 for {name}")

    return apiKey + "-" + APP_TYPE + ":" + validate_authcode_result[1]


def handler(event, context):
    users = getAllUsers()

    for user in users:
        try:
            name = user["name"]
            accessToken = login(user=user)
            saveAccessToken(user=user, accessToken=accessToken)
            sendTelegramMsg(f"{name}'s login to fyers was successful")
        except Exception as e:
            name = user["name"]
            print("Something went wrong", e)
            traceback.print_exc()
            sendTelegramMsg(f"{name}'s login to fyers failed, Something went wrong")

    return "success"
