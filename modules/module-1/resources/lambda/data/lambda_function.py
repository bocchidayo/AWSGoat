import json
import boto3
import traceback
import base64
from datetime import datetime, timedelta
import urllib
import os
import jwt
import bcrypt


def generateResponse(statusCode, body):
    return {
        "statusCode": statusCode,
        "body": body,
        "headers": {
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Origin": "*",
        },
    }


def download_url(url):
    # Remediation (SSRF): the URL used to be fetched with no validation at
    # all, letting an authenticated user make the Lambda request arbitrary
    # internal/link-local addresses (e.g. the instance metadata endpoint) and
    # exfiltrate the response through the resulting S3 object. Only plain
    # http(s) URLs resolving to a public address are now allowed.
    import ipaddress
    import socket

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Unsupported URL")

    try:
        resolved_ips = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        raise ValueError("Could not resolve host")

    for family, _, _, _, sockaddr in resolved_ips:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        ):
            raise ValueError("Requests to internal/link-local addresses are not allowed")

    req = urllib.request.Request(url, headers={"User-Agent": "Magic Browser"})
    image = urllib.request.urlopen(req, timeout=5).read()

    return image


def upload_file(img_data, bucket, url=None):

    object_name = "images/" + datetime.utcnow().strftime("%Y%m%d%H%M%S%f") + ".png"
    s3 = boto3.resource("s3")
    obj = s3.Object(bucket, object_name)
    file_b64 = ""

    if url == True:
        file = download_url(img_data)
        print(file)
    else:
        file = base64.b64decode(img_data)
    try:
        obj.put(Body=file, ACL="public-read")
        location = "us-east-1"
        object_url = "https://%s.s3.amazonaws.com/%s" % (bucket, object_name)
        return object_url
    except Exception as e:
        print(str(e))
        return "Please try with another image"


def generate_auth(userInfo):
    if userInfo is not None:
        JWT_SECRET = os.environ["JWT_SECRET"]
        userInfo = json.loads(userInfo)
        userInfo["exp"] = datetime.now() + timedelta(seconds=36000)
        return jwt.encode(payload=userInfo, key=JWT_SECRET, algorithm="HS256")
    else:
        return None


def get_auth_claims(event):
    # Remediation (broken access control): every privileged endpoint below
    # used to trust an "authLevel" (and sometimes "email"/"id") field taken
    # straight from the client-supplied request body - any self-registered
    # user (default authLevel "200") could simply send authLevel="0" and act
    # as an administrator, ban/delete/promote any user, or reset anyone's
    # password. Authorization now always comes from the claims embedded in
    # the signed JWT (set once, server-side, at login) instead.
    JWT_SECRET = os.environ["JWT_SECRET"]
    token = None
    if "JWT_TOKEN" in event["headers"]:
        token = event["headers"]["JWT_TOKEN"]
    elif "jwt_token" in event["headers"]:
        token = event["headers"]["jwt_token"]
    else:
        return None

    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        print("Token expired. Get new one")
        return None
    except jwt.InvalidTokenError:
        print("Invalid Token")
        return None


def auth_is_valid(event):
    return get_auth_claims(event) is not None


def lambda_handler(event, context):
    print(event)
    responses = ""
    userTable = os.environ.get("USERS_TABLE", "blog-users")
    postsTable = os.environ.get("POSTS_TABLE", "blog-posts")

    dynamodb = boto3.resource("dynamodb")
    dbUserTable = dynamodb.Table(userTable)
    dbPostTable = dynamodb.Table(postsTable)

    # Remediation: "/dump" used to return the full users table (bcrypt
    # hashes, password-reset secret question/answer) and the full posts
    # table with zero authentication. There is no legitimate product use
    # case for this route, so it is removed entirely rather than gated.

    if event["httpMethod"] == "POST" and event["path"] == "/register":
        data = json.loads(event["body"])
        new_user = {}
        if "email" in data:
            new_user["email"] = data["email"].lower().strip()
        if "address" in data:
            new_user["address"] = data["address"]
        if "country" in data:
            new_user["country"] = data["country"]
        if "name" in data:
            new_user["name"] = data["name"]
        if "phone" in data:
            new_user["phone"] = data["phone"]
        if "secretQuestion" in data:
            new_user["secretQuestion"] = data["secretQuestion"]
        if "secretAnswer" in data:
            new_user["secretAnswer"] = data["secretAnswer"]
        if "username" in data:
            new_user["username"] = data["username"].lower().strip()
        if "password" in data:
            new_user["password"] = data["password"].encode("utf-8").strip()
        if "creationDate" in data:
            new_user["creationDate"] = data["creationDate"]
        required_info = [
            "email",
            "username",
            "password",
            "country",
            "secretQuestion",
            "secretAnswer",
        ]

        for field in required_info:
            if field not in new_user:
                return generateResponse(200, "Fields required")

        new_user["authLevel"] = "200"
        new_user["userStatus"] = "active"

        response = dbUserTable.scan()
        items = response["Items"]

        while "LastEvaluatedKey" in response:
            response = dbUserTable.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response["Items"])

        check_user_email = dbUserTable.get_item(Key={"email": new_user["email"]})
        if "Item" in check_user_email:
            responses = "User with email already exists. Please choose a different email address"
            return generateResponse(200, json.dumps({"body": responses}))

        new_user["id"] = str(len(items) + 1)

        new_user["password"] = bcrypt.hashpw(
            new_user["password"], bcrypt.gensalt(rounds=10)
        ).decode("utf-8")
        dbUserTable.put_item(Item=new_user)
        responses = "User Registered"
        return generateResponse(200, json.dumps({"body": responses}))

    if event["httpMethod"] == "POST" and event["path"] == "/login":
        data = json.loads(event["body"])

        user_email = data["email"]
        user_password = data["password"].encode("utf-8")
        db_user = dbUserTable.get_item(Key={"email": user_email})

        if "Item" not in db_user:
            responses = "User with email " + user_email + " not found"
            return generateResponse(401, json.dumps({"body": responses}))
        db_user["Item"]["password"] = db_user["Item"]["password"].encode("utf-8")
        if user_email != db_user["Item"]["email"]:
            responses = "User with email " + user_email + " not found"
            return generateResponse(401, json.dumps({"body": responses}))
        if db_user["Item"]["userStatus"] == "banned":
            responses = "User is banned. Please contact your administrator"
            return generateResponse(401, json.dumps({"body": responses}))
        if not bcrypt.checkpw(user_password, db_user["Item"]["password"]):
            responses = "Incorrect Password!!"
            return generateResponse(401, json.dumps({"body": responses}))

        userInfo = {
            "email": db_user["Item"]["email"],
            "name": db_user["Item"]["name"],
            "authLevel": db_user["Item"]["authLevel"],
            "address": db_user["Item"]["address"],
            "country": db_user["Item"]["country"],
            "phone": db_user["Item"]["phone"],
            "secretQuestion": db_user["Item"]["secretQuestion"],
            "secretAnswer": db_user["Item"]["secretAnswer"],
            "username": db_user["Item"]["username"],
            "id": db_user["Item"]["id"],
        }

        gen_token = generate_auth(json.dumps(userInfo))
        responses = {"user": userInfo, "token": gen_token}
        return generateResponse(200, json.dumps({"body": responses}))

    if event["httpMethod"] == "POST" and event["path"] == "/reset-password":
        data = json.loads(event["body"])

        if (
            "email" not in data
            or "secretQuestion" not in data
            or "secretAnswer" not in data
            or "password" not in data
        ):
            responses = "All fields are required"
            return generateResponse(200, json.dumps({"body": responses}))

        email = data["email"].lower().strip()
        secretQuestion = data["secretQuestion"]
        secretAnswer = data["secretAnswer"]
        newPassword = data["password"].encode("utf-8")

        user_data = dbUserTable.get_item(Key={"email": email})
        if "Item" not in user_data:
            responses = "User does not exists"
            return generateResponse(200, json.dumps({"body": responses}))
        user_data = user_data["Item"]
        if (
            user_data["secretQuestion"] != secretQuestion
            or user_data["secretAnswer"] != secretAnswer
        ):
            responses = "Secret question or key doesn't match"
            return generateResponse(200, json.dumps({"body": responses}))

        encryptedPW = bcrypt.hashpw(newPassword, bcrypt.gensalt(rounds=10)).decode(
            "utf-8"
        )
        update_response = dbUserTable.update_item(
            Key={
                "email": email,
            },
            UpdateExpression="set password = :r",
            ExpressionAttributeValues={
                ":r": encryptedPW,
            },
            ReturnValues="UPDATED_NEW",
        )
        responses = "User " + email + " password updated"
        return generateResponse(200, json.dumps({"body": responses}))

    elif event["httpMethod"] == "POST" and event["path"] == "/list-posts":

        if event["body"] is None:
            response = dbPostTable.scan()
            items = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbPostTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                items.extend(response["Items"])
            for item in items:
                if item["postStatus"] != "approved":
                    items.remove(item)
            for item in items:
                if item["postStatus"] != "approved":
                    items.remove(item)

            return generateResponse(200, json.dumps({"body": items}))

        # Remediation (broken access control): authLevel/email used to come
        # straight from the request body, so any anonymous caller could pass
        # authLevel="0" and see every post regardless of status. This view
        # (non-null body) is the privileged one, so it now requires a valid
        # session and takes authLevel/email from the verified JWT.
        claims = get_auth_claims(event)
        if claims is None:
            return generateResponse(401, json.dumps({"body": "Invalid Authorization"}))
        data = json.loads(event["body"])
        authLevel = claims.get("authLevel")
        postStatus = data["postStatus"]
        email = claims.get("email")

        response = dbPostTable.scan()
        items = response["Items"]

        while "LastEvaluatedKey" in response:
            response = dbPostTable.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response["Items"])

        # postStatus - > accepted, rejected, pending, all
        responses = []
        if authLevel == "0" or authLevel == "100":
            if postStatus != "all":
                for i in range(len(items)):
                    item = items[i]
                    if item["postStatus"] == postStatus:
                        responses.append(item)
            else:
                for i in range(len(items)):
                    item = items[i]
                    responses.append(item)
        else:
            if postStatus != "all":
                for i in range(len(items)):
                    item = items[i]
                    if item["postStatus"] == postStatus and item["email"] == email:
                        responses.append(item)
            else:
                for i in range(len(items)):
                    item = items[i]
                    if item["email"] == email:
                        responses.append(item)

        return generateResponse(200, json.dumps({"body": responses}))

    claims = get_auth_claims(event)
    if claims is not None:
        callerAuthLevel = claims.get("authLevel")
        callerEmail = claims.get("email")
        callerId = claims.get("id")

        if event["httpMethod"] == "POST" and event["path"] == "/change-password":
            data = json.loads(event["body"])

            id = data["id"].strip()

            # Remediation (broken access control): "id" used to be trusted
            # straight from the request body with no ownership check at all,
            # and ids are small sequential integers - any authenticated user
            # (including a freshly self-registered one) could reset any other
            # user's password, including an administrator's. Only the
            # caller's own id is allowed unless the caller is an admin.
            if id != str(callerId) and callerAuthLevel != "0":
                return generateResponse(403, json.dumps({"body": "Forbidden"}))

            if "newPassword" not in data or "confirmNewPassword" not in data:
                responses = "New password & Confirm new password are mandatory"
                return generateResponse(200, json.dumps({"body": responses}))

            newPassword = data["newPassword"].strip()
            confirmNewPassword = data["confirmNewPassword"].strip()

            if newPassword != confirmNewPassword:
                responses = "New password & Confirm new password must match"
                return generateResponse(200, json.dumps({"body": responses}))

            email = ""
            response = dbUserTable.scan()
            items = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbUserTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                items.extend(response["Items"])

            print(items)
            for item in items:
                if item["id"] == id:
                    email = item["email"]
                    break

            encryptedPW = bcrypt.hashpw(
                newPassword.encode("utf-8"), bcrypt.gensalt(rounds=10)
            ).decode("utf-8")

            update_response = dbUserTable.update_item(
                Key={
                    "email": email,
                },
                UpdateExpression="set password = :r",
                ExpressionAttributeValues={
                    ":r": encryptedPW,
                },
                ReturnValues="UPDATED_NEW",
            )

            responses = "Password changed successfully"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/ban-user":
            data = json.loads(event["body"])

            if "name" not in data or "email" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            name = data["name"]
            authLevel = callerAuthLevel
            email = data["email"]

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))
            check_user = check_user["Item"]
            if check_user["userStatus"] == "banned":
                responses = "User already banned"
                return generateResponse(200, json.dumps({"body": responses}))
            else:
                update_response = dbUserTable.update_item(
                    Key={
                        "email": email,
                    },
                    UpdateExpression="set userStatus = :r",
                    ExpressionAttributeValues={
                        ":r": "banned",
                    },
                    ReturnValues="UPDATED_NEW",
                )
                responses = "User " + email + " Banned"
                return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/unban-user":
            data = json.loads(event["body"])

            if "name" not in data or "email" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            name = data["name"]
            authLevel = callerAuthLevel
            email = data["email"]

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))
            check_user = check_user["Item"]
            if check_user["userStatus"] != "banned":
                responses = "User already Unbanned"
                return generateResponse(200, json.dumps({"body": responses}))
            else:
                update_response = dbUserTable.update_item(
                    Key={
                        "email": email,
                    },
                    UpdateExpression="set userStatus = :r",
                    ExpressionAttributeValues={
                        ":r": "active ",
                    },
                    ReturnValues="UPDATED_NEW",
                )
                responses = "User " + email + " Unbanned"
                return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/user-details-modal":
            data = json.loads(event["body"])
            email = data["email"]

            responses = dbPostTable.scan(
                FilterExpression="email = :a",
                ExpressionAttributeValues={
                    ":a": email,
                },
                ProjectionExpression="authorName, postContent, postingDate, postTitle, id, getRequestImageData",
            )

            return generateResponse(200, json.dumps({"body": responses}))

        # Remediation: "/xss" was a debug endpoint that reflected
        # "scriptValue" back verbatim with no encoding - a stored/reflected
        # XSS sink with no product purpose. Removed.

        elif event["path"] == "/save-content":
            bucket = "replace-bucket-name"
            if event["httpMethod"] == "POST":
                img_data = json.loads(event["body"])["value"]
                # print(img_data)
                responses = upload_file(img_data, bucket)
                print(responses)
                return generateResponse(200, json.dumps({"body": responses}))
                # Decode base64 and upload to s3

            elif event["httpMethod"] == "GET":
                # print(event)
                # Download from url as base64 and upload to s3
                img_data = event["queryStringParameters"]["value"]
                print(img_data)
                try:
                    responses = upload_file(img_data, bucket, True)
                except ValueError as e:
                    return generateResponse(400, json.dumps({"body": str(e)}))
                return generateResponse(200, json.dumps({"body": responses}))
            else:
                return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/search-author":

            client = boto3.client("dynamodb")
            data = json.loads(event["body"])
            if "value" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))
            name = data["value"]
            authLevel = callerAuthLevel
            try:
                # Remediation (PartiQL injection): "name" used to be concatenated
                # directly into the statement (attack-manuals/module-1/02-SQL
                # Injection.md - payload "value":"hello' or '1'='1" against this
                # exact endpoint). PartiQL's native "?" + Parameters binding is
                # used instead so the value is never parsed as query syntax.
                if authLevel == "200":
                    exec_statement = (
                        'SELECT * FROM "' + userTable + '" where name = ? '
                        + "and authLevel in ('200','100');"
                    )
                elif authLevel == "100":
                    exec_statement = (
                        'SELECT * FROM "' + userTable + '" where name = ? '
                        + "and authLevel in ('200','100','0');"
                    )
                else:
                    exec_statement = (
                        'SELECT * FROM "' + userTable + '" where name = ?;'
                    )

                responses = client.execute_statement(
                    Statement=exec_statement, Parameters=[{"S": name}]
                )
                if responses["Items"] != {}:
                    for item in responses["Items"]:
                        if "email" in item:
                            item["email"] = item["email"]["S"]
                        if "address" in item:
                            item["address"] = item["address"]["S"]
                        if "country" in item:
                            item["country"] = item["country"]["S"]
                        if "name" in item:
                            item["name"] = item["name"]["S"]
                        if "phone" in item:
                            item["phone"] = item["phone"]["S"]
                        if "secretQuestion" in item:
                            item["secretQuestion"] = ""
                        if "secretAnswer" in item:
                            item["secretAnswer"] = ""
                        if "username" in item:
                            item["username"] = item["username"]["S"]
                        if "password" in item:
                            item["password"] = ""
                        if "id" in item:
                            item["id"] = item["id"]["S"]
                        if "userStatus" in item:
                            item["userStatus"] = item["userStatus"]["S"]
                        if "authLevel" in item:
                            item["authLevel"] = item["authLevel"]["S"]
                        if "creationDate" in item:
                            item["creationDate"] = item["creationDate"]["S"]

                print("Response ", responses)
                return generateResponse(200, json.dumps({"body": responses}))
            except:
                print("Except block")
                return generateResponse(500, json.dumps(str(traceback.format_exc())))

        elif event["httpMethod"] == "POST" and event["path"] == "/get-users":
            print("inside get-users level")
            client = boto3.client("dynamodb")
            data = json.loads(event["body"])
            authLevel = callerAuthLevel
            print("got auth level")
            try:
                if authLevel == "200":
                    exec_statement = 'SELECT * FROM "' + userTable + "\" where authLevel in ('200','100');"
                elif authLevel == "100":
                    exec_statement = 'SELECT * FROM "' + userTable + "\" where authLevel in ('200','100','0');"
                else:
                    exec_statement = 'SELECT * FROM "' + userTable + '";'

                print(exec_statement)
                responses = client.execute_statement(Statement=exec_statement)
                print(responses)
                if responses["Items"] != {}:
                    for item in responses["Items"]:
                        if "email" in item:
                            item["email"] = item["email"]["S"]
                        if "address" in item:
                            item["address"] = item["address"]["S"]
                        if "country" in item:
                            item["country"] = item["country"]["S"]
                        if "name" in item:
                            item["name"] = item["name"]["S"]
                        if "phone" in item:
                            item["phone"] = item["phone"]["S"]
                        if "secretQuestion" in item:
                            item["secretQuestion"] = ""
                        if "secretAnswer" in item:
                            item["secretAnswer"] = ""
                        if "username" in item:
                            item["username"] = item["username"]["S"]
                        if "password" in item:
                            item["password"] = ""
                        if "id" in item:
                            item["id"] = item["id"]["S"]
                        if "userStatus" in item:
                            item["userStatus"] = item["userStatus"]["S"]
                        if "authLevel" in item:
                            item["authLevel"] = item["authLevel"]["S"]
                        if "creationDate" in item:
                            item["creationDate"] = item["creationDate"]["S"]

                print("Response ", responses)
                return generateResponse(200, json.dumps({"body": responses}))
            except Exception as e:
                print("Except block ", e)
                return generateResponse(500, json.dumps(str(traceback.format_exc())))

        elif event["httpMethod"] == "POST" and event["path"] == "/delete-user":
            data = json.loads(event["body"])

            if "email" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            authLevel = callerAuthLevel
            email = data["email"]

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))

            delete_response = dbUserTable.delete_item(
                Key={
                    "email": email,
                }
            )
            responses = "User " + email + " deleted"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/change-auth":
            data = json.loads(event["body"])

            if (
                "email" not in data
                or "userAuthLevel" not in data
            ):
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            authLevel = callerAuthLevel
            email = data["email"]
            userAuthLevel = data["userAuthLevel"].strip()

            if authLevel != "0":
                responses = "Requires Admin"
                return generateResponse(200, json.dumps({"body": responses}))

            if userAuthLevel == "Reassign as Admin":
                userAuthLevel = "0"
            elif userAuthLevel == "Reassign as Author":
                userAuthLevel = "200"
            elif userAuthLevel == "Reassign as Editor":
                userAuthLevel = "100"

            check_user = dbUserTable.get_item(Key={"email": email})
            if "Item" not in check_user:
                responses = "User does not exists"
                return generateResponse(200, json.dumps({"body": responses}))

            update_response = dbUserTable.update_item(
                Key={
                    "email": email,
                },
                UpdateExpression="set authLevel = :r",
                ExpressionAttributeValues={
                    ":r": userAuthLevel,
                },
                ReturnValues="UPDATED_NEW",
            )

            responses = "User " + email + " AuthLevel Updated"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/modify-post-status":
            data = json.loads(event["body"])

            if "postStatus" not in data or "id" not in data:
                responses = "Something is missing. Please check proper authentication"
                return generateResponse(200, json.dumps({"body": responses}))

            authLevel = callerAuthLevel
            id = data["id"]
            postStatus = data["postStatus"].lower().strip()

            if not (authLevel == "0" or authLevel == "100"):
                responses = "Requires Admin or Editor"
                return generateResponse(200, json.dumps({"body": responses}))

            check_post = dbPostTable.get_item(Key={"id": id})
            if "Item" not in check_post:
                responses = "Post does not exists"
                return generateResponse(200, json.dumps({"body": responses}))

            update_response = dbPostTable.update_item(
                Key={
                    "id": id,
                },
                UpdateExpression="set postStatus = :r",
                ExpressionAttributeValues={
                    ":r": postStatus,
                },
                ReturnValues="UPDATED_NEW",
            )

            responses = "Post " + id + " status Updated"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/change-profile":
            data = json.loads(event["body"])
            print("change-proifile called")
            new_user_data = {}
            if "email" in data:
                new_user_data["email"] = data["email"].lower().strip()
            if "address" in data:
                new_user_data["address"] = data["address"]
            if "country" in data:
                new_user_data["country"] = data["country"]
            if "name" in data:
                new_user_data["name"] = data["name"]
            if "phone" in data:
                new_user_data["phone"] = data["phone"]
            if "secretQuestion" in data:
                new_user_data["secretQuestion"] = data["secretQuestion"]
            if "secretAnswer" in data:
                new_user_data["secretAnswer"] = data["secretAnswer"]
            if "username" in data:
                new_user_data["username"] = data["username"].lower().strip()

            required_info = [
                "email",
                "address",
                "name",
                "phone",
                "username",
                "country",
                "secretQuestion",
                "secretAnswer",
            ]

            for field in required_info:
                if field not in new_user_data:
                    return generateResponse(200, "All Fields required")

            new_user_data["userStatus"] = "active"

            update_response = dbUserTable.update_item(
                Key={
                    "email": new_user_data["email"],
                },
                UpdateExpression="set address = :v1, country = :v5, #nm = :v2, phone= :v3, username = :v4,  secretQuestion = :v6, secretAnswer = :v7",
                ExpressionAttributeValues={
                    ":v1": new_user_data["address"],
                    ":v2": new_user_data["name"],
                    ":v3": new_user_data["phone"],
                    ":v4": new_user_data["username"],
                    ":v5": new_user_data["country"],
                    ":v6": new_user_data["secretQuestion"],
                    ":v7": new_user_data["secretAnswer"],
                },
                ExpressionAttributeNames={"#nm": "name"},
                ReturnValues="UPDATED_NEW",
            )
            print(update_response)
            responses = update_response["Attributes"]
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/save-post":
            data = json.loads(event["body"])
            new_post = {}
            if "postTitle" in data:
                new_post["postTitle"] = data["postTitle"]
            if "authorName" in data:
                new_post["authorName"] = data["authorName"]
            if "postingDate" in data:
                new_post["postingDate"] = data["postingDate"]
            if "email" in data:
                new_post["email"] = data["email"]
            if "postContent" in data:
                new_post["postContent"] = data["postContent"]
            if "getRequestImageData" in data:
                new_post["getRequestImageData"] = data["getRequestImageData"]

            required_info = [
                "postTitle",
                "authorName",
                "postingDate",
                "email",
                "postContent",
                "getRequestImageData",
            ]

            for field in required_info:
                if field not in new_post:
                    return generateResponse(200, "Fields required")

            new_post["postStatus"] = "pending"

            response = dbPostTable.scan()
            items = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbPostTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                items.extend(response["Items"])

            new_post["id"] = str(len(items) + 1)

            dbPostTable.put_item(Item=new_post)
            responses = "Post Added"
            return generateResponse(200, json.dumps({"body": responses}))

        elif event["httpMethod"] == "POST" and event["path"] == "/get-dashboard":

            currentYear = str(datetime.now().year)
            response = dbUserTable.scan()
            users = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbUserTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                users.extend(response["Items"])

            response = dbPostTable.scan()
            posts = response["Items"]

            while "LastEvaluatedKey" in response:
                response = dbPostTable.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
                posts.extend(response["Items"])

            total_posts = str(len(posts))
            total_users = str(len(users))

            print("Total Posts: " + total_posts)
            print("Total Users: " + total_users)
            data = {}

            for post in posts:
                postingdate = post["postingDate"]
                print(postingdate)
                if postingdate[:7] in data:
                    data[postingdate[:7]] = data[postingdate[:7]] + 1
                else:
                    if postingdate[:4] == currentYear:
                        data[postingdate[:7]] = 1

            for i in range(1, 13):
                mm = str(i).zfill(2)
                key = currentYear + "-" + mm
                if key not in data:
                    data[key] = 0

            new_data = {}
            for i in range(1, 13):
                mm = str(i).zfill(2)
                key = currentYear + "-" + mm
                new_data[key] = data[key]

            chartLabels = list(new_data.keys())
            chartData = list(new_data.values())

            for i in range(len(chartLabels)):
                label = chartLabels[i]
                yyyy = label[:4]
                mm = label[5:7]
                lab = mm + "/01/" + yyyy
                chartLabels[i] = lab

            recent_user_names = []
            recent_user_times = []
            for user in users:
                createtime = datetime.strptime(user["creationDate"][:10], "%Y-%m-%d")
                recent_user_names.append(user["name"])
                recent_user_times.append(createtime)

            top_recent_users = []
            top_recent_times = []

            for i in range(5):
                list_index = recent_user_times.index(max(recent_user_times))
                top_recent_times.append(
                    recent_user_times[list_index].strftime("%d %b %Y")
                )
                top_recent_users.append(recent_user_names[list_index])
                del recent_user_names[list_index]
                del recent_user_times[list_index]

            responses = {
                "totalPosts": total_posts,
                "totalUsers": total_users,
                "chartLabel": chartLabels,
                "chartData": chartData,
                "recentUserNames": top_recent_users,
                "recentUserDates": top_recent_times,
            }
            print(responses)
            return generateResponse(200, json.dumps({"body": responses}))

        else:
            return generateResponse(200, json.dumps({"body": responses}))

    responses = "Invalid Authorization"
    return generateResponse(401, json.dumps({"body": responses}))
