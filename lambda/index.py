import contextlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import urllib.parse
from urllib.request import Request, urlopen
from uuid import uuid4
from zipfile import ZipFile

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

cloudfront = boto3.client('cloudfront')
s3 = boto3.client('s3')

CFN_SUCCESS = "SUCCESS"
CFN_FAILED = "FAILED"
ENV_KEY_MOUNT_PATH = "MOUNT_PATH"
ENV_KEY_SKIP_CLEANUP = "SKIP_CLEANUP"

AWS_CLI_CONFIG_FILE = "/tmp/aws_cli_config"
CUSTOM_RESOURCE_OWNER_TAG = "aws-cdk:cr-owned"

os.putenv('AWS_CONFIG_FILE', AWS_CLI_CONFIG_FILE)

def handler(event, context):
    try:
        print("Received event:", json.dumps(event))

        # リクエストボディの解析
        body = json.loads(event['body'])
        message = body['message']
        conversation_history = body.get('conversationHistory', [])

        # 会話履歴は今回は使わず、messageだけ送るシンプル版
        payload = {
            "message": message
        }

        # あなたのFastAPIサーバーのURLを書く！（/predictにPOST）
        api_url = "https://4b02-34-82-199-167.ngrok-free.app"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            api_url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        # APIリクエスト送信
        with urllib.request.urlopen(req) as res:
            response_body = res.read()
            response_json = json.loads(response_body.decode("utf-8"))

        # レスポンスからアシスタントの返答を取り出す
        assistant_response = response_json.get("response", "")

        # 成功レスポンスを返す
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
                "Access-Control-Allow-Methods": "OPTIONS,POST"
            },
            "body": json.dumps({
                "success": True,
                "response": assistant_response,
                "conversationHistory": conversation_history + [
                    {"role": "user", "content": message},
                    {"role": "assistant", "content": assistant_response}
                ]
            })
        }

    except Exception as error:
        print("Error:", str(error))
        
        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
                "Access-Control-Allow-Methods": "OPTIONS,POST"
            },
            "body": json.dumps({
                "success": False,
                "error": str(error)
            })
        }

#---------------------------------------------------------------------------------------------------
# Sanitize the message to mitigate CWE-117 and CWE-93 vulnerabilities
def sanitize_message(message):
    if not message:
        return message

    # Sanitize the message to prevent log injection and HTTP response splitting
    sanitized_message = message.replace('\n', '').replace('\r', '')

    # Encode the message to handle special characters
    encoded_message = urllib.parse.quote(sanitized_message)

    return encoded_message

#---------------------------------------------------------------------------------------------------
# populate all files from s3_source_zips to a destination bucket
def s3_deploy(s3_source_zips, s3_dest, user_metadata, system_metadata, prune, exclude, include, source_markers, extract, source_markers_config):
    # list lengths are equal
    if len(s3_source_zips) != len(source_markers):
        raise Exception("'source_markers' and 's3_source_zips' must be the same length")

    # create a temporary working directory in /tmp or if enabled an attached efs volume
    if ENV_KEY_MOUNT_PATH in os.environ:
        workdir = os.getenv(ENV_KEY_MOUNT_PATH) + "/" + str(uuid4())
        os.mkdir(workdir)
    else:
        workdir = tempfile.mkdtemp()

    logger.info("| workdir: %s" % workdir)

    # create a directory into which we extract the contents of the zip file
    contents_dir=os.path.join(workdir, 'contents')
    os.mkdir(contents_dir)

    try:
        # download the archive from the source and extract to "contents"
        for i in range(len(s3_source_zips)):
            s3_source_zip = s3_source_zips[i]
            markers       = source_markers[i]
            markers_config = source_markers_config[i]

            if extract:
                archive=os.path.join(workdir, str(uuid4()))
                logger.info("archive: %s" % archive)
                aws_command("s3", "cp", s3_source_zip, archive)
                logger.info("| extracting archive to: %s\n" % contents_dir)
                logger.info("| markers: %s" % markers)
                extract_and_replace_markers(archive, contents_dir, markers, markers_config)
            else:
                logger.info("| copying archive to: %s\n" % contents_dir)
                aws_command("s3", "cp", s3_source_zip, contents_dir)

        # sync from "contents" to destination

        s3_command = ["s3", "sync"]

        if prune:
          s3_command.append("--delete")

        if exclude:
          for filter in exclude:
            s3_command.extend(["--exclude", filter])

        if include:
          for filter in include:
            s3_command.extend(["--include", filter])

        s3_command.extend([contents_dir, s3_dest])
        s3_command.extend(create_metadata_args(user_metadata, system_metadata))
        aws_command(*s3_command)
    finally:
        if not os.getenv(ENV_KEY_SKIP_CLEANUP):
            shutil.rmtree(workdir)

#---------------------------------------------------------------------------------------------------
# invalidate files in the CloudFront distribution edge caches
def cloudfront_invalidate(distribution_id, distribution_paths):
    invalidation_resp = cloudfront.create_invalidation(
        DistributionId=distribution_id,
        InvalidationBatch={
            'Paths': {
                'Quantity': len(distribution_paths),
                'Items': distribution_paths
            },
            'CallerReference': str(uuid4()),
        })
    # by default, will wait up to 10 minutes
    cloudfront.get_waiter('invalidation_completed').wait(
        DistributionId=distribution_id,
        Id=invalidation_resp['Invalidation']['Id'])

#---------------------------------------------------------------------------------------------------
# set metadata
def create_metadata_args(raw_user_metadata, raw_system_metadata):
    if len(raw_user_metadata) == 0 and len(raw_system_metadata) == 0:
        return []

    format_system_metadata_key = lambda k: k.lower()
    format_user_metadata_key = lambda k: k.lower()

    system_metadata = { format_system_metadata_key(k): v for k, v in raw_system_metadata.items() }
    user_metadata = { format_user_metadata_key(k): v for k, v in raw_user_metadata.items() }

    flatten = lambda l: [item for sublist in l for item in sublist]
    system_args = flatten([[f"--{k}", v] for k, v in system_metadata.items()])
    user_args = ["--metadata", json.dumps(user_metadata, separators=(',', ':'))] if len(user_metadata) > 0 else []

    return system_args + user_args + ["--metadata-directive", "REPLACE"]

#---------------------------------------------------------------------------------------------------
# executes an "aws" cli command
def aws_command(*args):
    aws="/opt/awscli/aws" # from AwsCliLayer
    logger.info("| aws %s" % ' '.join(args))
    subprocess.check_call([aws] + list(args))

#---------------------------------------------------------------------------------------------------
# sends a response to cloudformation
def cfn_send(event, context, responseStatus, responseData={}, physicalResourceId=None, noEcho=False, reason=None):

    responseUrl = event['ResponseURL']

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = reason or ('See the details in CloudWatch Log Stream: ' + context.log_stream_name)
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData

    body = json.dumps(responseBody)
    logger.info("| response body:\n" + body)

    headers = {
        'content-type' : '',
        'content-length' : str(len(body))
    }

    try:
        request = Request(responseUrl, method='PUT', data=bytes(body.encode('utf-8')), headers=headers)
        with contextlib.closing(urlopen(request)) as response:
            logger.info("| status code: " + response.reason)
    except Exception as e:
        logger.error("| unable to send response to CloudFormation")
        logger.exception(e)


#---------------------------------------------------------------------------------------------------
# check if bucket is owned by a custom resource
# if it is then we don't want to delete content
def bucket_owned(bucketName, keyPrefix):
    tag = CUSTOM_RESOURCE_OWNER_TAG
    if keyPrefix != "":
        tag = tag + ':' + keyPrefix
    try:
        request = s3.get_bucket_tagging(
            Bucket=bucketName,
        )
        return any((x["Key"].startswith(tag)) for x in request["TagSet"])
    except Exception as e:
        logger.info("| error getting tags from bucket")
        logger.exception(e)
        return False

# extract archive and replace markers in output files
def extract_and_replace_markers(archive, contents_dir, markers, markers_config):
    with ZipFile(archive, "r") as zip:
        zip.extractall(contents_dir)

        # replace markers for this source
        for file in zip.namelist():
            file_path = os.path.join(contents_dir, file)
            if os.path.isdir(file_path): continue
            replace_markers(file_path, markers, markers_config)

def prepare_json_safe_markers(markers):
    """Pre-process markers to ensure JSON-safe values"""
    safe_markers = {}
    for key, value in markers.items():
        # Serialize the value as JSON to handle escaping if the value is a string
        serialized = json.dumps(value)
        if serialized.startswith('"') and serialized.endswith('"'):
            json_safe_value = json.dumps(value)[1:-1]  # Remove surrounding quotes
        else:
            json_safe_value = serialized
        safe_markers[key.encode('utf-8')] = json_safe_value.encode('utf-8')
    return safe_markers

def replace_markers(filename, markers, markers_config):
    """Replace markers in a file, with special handling for JSON files."""
    # if there are no markers, skip
    if not markers:
        return
    
    outfile = filename + '.new'
    json_escape = markers_config.get('jsonEscape', 'false').lower()
    if json_escape == 'true':
        replace_tokens = prepare_json_safe_markers(markers)
    else:
        replace_tokens = dict([(k.encode('utf-8'), v.encode('utf-8')) for k, v in markers.items()])

    # Handle content with line-by-line binary replacement
    with open(filename, 'rb') as fi, open(outfile, 'wb') as fo:
        # Process line by line to handle large files
        for line in fi:
            for token, replacement in replace_tokens.items():
                line = line.replace(token, replacement)
            fo.write(line)

    # Delete the original file and rename the new one to the original
    os.remove(filename)
    os.rename(outfile, filename)

def replace_markers_in_json(json_object, replace_tokens):
    """Replace markers in JSON content with proper escaping."""
    try:
        def replace_in_structure(obj):
            if isinstance(obj, str):
                # Convert string to bytes for consistent replacement
                result = obj.encode('utf-8')
                for token, replacement in replace_tokens.items():
                    result = result.replace(token, replacement)
                # Convert back to string
                return result.decode('utf-8')
            elif isinstance(obj, dict):
                return {k: replace_in_structure(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_in_structure(item) for item in obj]
            return obj

        # Process the whole structure
        processed = replace_in_structure(json_object)
        return json.dumps(processed)
    except Exception as e:
        logger.error(f'Error processing JSON: {e}')
        logger.exception(e)
        return json_object

