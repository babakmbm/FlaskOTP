from twilio.rest import Client

account_sid = 'AC563feb6b230d4ff71e48d4ce4ce627fb'
auth_token = '629e166d8866227e9bb6e4dbdf5f233e'
client = Client(account_sid, auth_token)

message = client.messages.create(
    messaging_service_sid='MG1c5695a4134b9896ec7d219d3b656bbc',
    body='Your Code is: 123456',
    to='+447931772526'
)

print(message.sid)