#!/usr/bin/env python3
import os
import sys
import ConfigParser
import tweepy

class Bird(object):
    def __init__(self):
        self.consumer_key = None
        self.consumer_secret = None
        self.access_token = None
        self.access_token_secret = None
        self.api = None
        self._load_config()

    def _load_config(self):
        """Parse configuration file, returns a list of keys"""
        config = ConfigParser.ConfigParser()
        # search for ~/.trickybird
        if os.path.isfile(os.path.join(os.path.expanduser("~"), ".twitter")):
            conffile = os.path.join(os.path.expanduser("~"), ".twitter")
        else:
            print("Couldn't find the config file")
            sys.exit(1)
        config.read(conffile)
        keys = []
        try:
            for attr in ['consumer_key', 'consumer_secret', 'access_token', 'access_token_secret']:
                setattr(self, attr, config.get("twitter", attr))
        except ConfigParser.NoOptionError:
            pass

    def _authenticate(self):
        """
        Authenticate on twitter
        """
        auth = tweepy.OAuthHandler(self.consumer_key, self.consumer_secret)
        auth.set_access_token(self.access_token, self.access_token_secret)
        self.api = tweepy.API(auth)

    def get_profile_information(self, username):
        """
        Get profile information on an account
        """
        if self.api is None:
            self._authenticate()

        return self.api.get_user(screen_name=username)

    def get_user_tweets(self, username, since_id=None):
        """
        Download all tweets for an user
        Max is around 3200 tweets
        """
        if self.api is None:
            self._authenticate()
        tweets = []
        if since_id:
            cursor = tweepy.Cursor(self.api.user_timeline, screen_name=username, since_id=since_id)
        else:
            cursor = tweepy.Cursor(self.api.user_timeline, screen_name=username)

        for item in cursor.items():
            tweets.append(item)

        return tweets

    def get_searched_tweets(self, hashtag, since_id=None):
        """
        Search all tweets for a hashtag
        """
        if self.api is None:
            self._authenticate()

        tweets = []
        if since_id:
            cursor = tweepy.Cursor(self.api.search, q=hashtag, count=100, since_id=since_id)
        else:
            cursor = tweepy.Cursor(self.api.search, q=hashtag, count=100)
        try:
            for item in cursor.items():
                tweets.append(item)
        except tweepy.error.TweepError:
            print("Reached Twitter rate limit")
        return tweets

    def get_tweet(self, tweet_id):
        """
        Return a Tweepy status for this id
        """
        if self.api is None:
            self._authenticate()
        return self.api.get_status(tweet_id)

    def get_followers(self, user):
        """
        Return followers of this user
        """
        if self.api is None:
            self._authenticate()

        followers = []
        for page in tweepy.Cursor(self.api.followers, screen_name=user).pages():
            followers.extend(page)
        return followers

    def get_followers_ids(self, user):
        """
        Return followers of this user
        """
        if self.api is None:
            self._authenticate()

        followers = []
        for page in tweepy.Cursor(self.api.followers_ids, screen_name=user).pages():
            followers.extend(page)
        return followers

    def get_following(self, user):
        if self.api is None:
            self._authenticate()

        following = []
        for page in tweepy.Cursor(self.api.friends, screen_name=user).pages():
            following.extend(page)
        return following

    def get_following_ids(self, user):
        if self.api is None:
            self._authenticate()

        following = []
        for page in tweepy.Cursor(self.api.friends_ids, screen_name=user).pages():
            following.extend(page)
        return following

    def get_following(self, user):
        if self.api is None:
            self._authenticate()

        following = []
        for page in tweepy.Cursor(self.api.friends, screen_name=user).pages():
            following.extend(page)
