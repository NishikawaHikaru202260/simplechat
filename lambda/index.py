import json
import urllib.request

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
        api_url = "https://5864-34-82-199-167.ngrok-free.app"

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
