import argparse
import json
from bird import Bird


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check twitter easily')
    parser.add_argument('--user', '-u',
            help='Get user infos')
    parser.add_argument('--tweets', '-t',
            help='Download tweets of an user')
    parser.add_argument('--tweet', '-T',
            help='Download tweet with the given id')
    parser.add_argument('--save', '-s',
            help='save all infos about an user and their tweets')

    args = parser.parse_args()

    bird = Bird()

    if args.user:
        a = bird.get_profile_information(args.user)
        print json.dumps(a._json, sort_keys=True, indent=4, separators=(',', ': '))
    elif args.tweets:
        a = bird.get_user_tweets(args.tweets, limit=1000)
        for page in a:
            # FIXME : improve this
            print json.dumps(page, sort_keys=True, indent=4, separators=(',', ': '))
    elif args.tweet:
        a = bird.get_tweet(args.tweet)
        print json.dumps(a._json, sort_keys=True, indent=4, separators=(',', ': '))
    elif args.save:
        data = {}
        a = bird.get_profile_information(args.save)
        data["user"] = a._json
        b = bird.get_user_tweets(args.save)
        data["tweets"] = []
        for t in b:
            data["tweets"].append(t._json)
        print(json.dumps(data))
