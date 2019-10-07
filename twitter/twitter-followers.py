#!/usr/bin/env python3
import argparse
import tweepy
import json
import sys
import os.path
import json
from bird import Bird


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Get follower and following for some users')
    parser.add_argument('--user', '-u',
            help='Get user infos')
    parser.add_argument('--list', '-l',
            help='File containing list of user names')
    parser.add_argument('--file', '-f',
            help='File to store followers/following infos')

    args = parser.parse_args()
    bird = Bird()

    if args.user is None and args.list is None:
        print("Please give an username or a file")
        parser.print_help()
        sys.exit(1)

    if args.file:
        try:
            f = open(args.file, "r")
            fdata = f.read()
            f.close()
            if fdata != "":
                data = json.loads(fdata)
            else:
                data = {}
        except IOError:
            data = {}
    else:
        data = {}


    if args.user:
        if not args.user.startswith("@"):
            user = "@" + args.user
        else:
            user = args.user

        if user not in data:
            # Get followers ids
            followers = bird.get_followers_ids(user)
            print("%i followers" % len(followers))
            # Get following
            followings = bird.get_following_ids(user)
            print("%i following" % len(followings))
            # Get user info
            userinfo = bird.get_profile_information(user)
            data[user] = {
                    "id": userinfo.id,
                    "name": userinfo.name,
                    "screen_name": userinfo.screen_name,
                    "followers": followers,
                    "followings": followings
            }
            if args.file:
                f = open(args.file, "w")
                json.dump(data, f)
                f.close()
            else:
                print json.dumps(data, sort_keys=True,
                        indent=4, separators=(',', ': '))
        else:
            print("%s already in data" % user)

    elif args.list:
        f = open(args.list, 'r')
        users = f.read().split()
        f.close()
        for u in users:
            if not u.strip().startswith("@"):
                user = "@" + u.strip()
            else:
                user = u.strip()

            if user not in data:
                try:
                    print("Gathering infos on user %s" % user)
                    # Get followers ids
                    followers = bird.get_followers_ids(user)
                    print("%i followers" % len(followers))
                    # Get following
                    followings = bird.get_following_ids(user)
                    print("%i following" % len(followings))
                    # Get user info
                    userinfo = bird.get_profile_information(user)
                    data[user] = {
                            "id": userinfo.id,
                            "name": userinfo.name,
                            "screen_name": userinfo.screen_name,
                            "followers": followers,
                            "followings": followings
                    }
                except IOError:
                    pass
                except tweepy.error.RateLimitError:
                    print("Rate limit exceeded, stopping here")
                    break
                except tweepy.error.TweepError as e:
                    print("%s does not exist" % user)
            else:
                print("%s already in data" % user)
        if args.file:
            f = open(args.file, "w")
            json.dump(data, f)
            f.close()
        else:
            print json.dumps(data, sort_keys=True,
                    indent=4, separators=(',', ': '))


        pass
    #followers = bird.get_followers_ids(args.user)
    #print(followers)

