import argparse
from twilio.rest import Client


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("ACCOUNT_SID")
    parser.add_argument("AUTH_TOKEN")
    args = parser.parse_args()

    client = Client(args.ACCOUNT_SID, args.AUTH_TOKEN)

    messages = client.messages.list(limit=20)

    print("{} messages retrieved".format(len(messages)))
    for record in messages:
        print("{} -> {} : {}".format(
            record.from_,
            record.to,
            record.body
        ))
