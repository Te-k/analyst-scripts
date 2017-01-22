#! /usr/bin/env python

"""
    misp
    ~~~~

    Interface module to MISP servers (https://github.com/MISP/MISP).

    :copyright: Nicolas Bareil
    :license: Apache Licence, Version 2.0

"""
#    This file is part of python-misp.
#
#   Copyright 2015 Nicolas Bareil <nicolas.bareil@airbus.com>
#                  while at Airbus Group CERT <http://www.airbus.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import time
import datetime
import uuid
import os
import lxml
from lxml import objectify
import requests

TEST_NEEDLE = '68b329da9893e34099c7d8ad5cb9c940'
TEST_EVT_ID = 540
TEST_ATTR_ID = 87516
TEST_LAST_EVT_ID = 534

DEFAULT_MISP_URL = 'https://misp.internal'
DEFAULT_ORG = 'Default ACME Corp'
DEFAULT_ORGC = DEFAULT_ORG
try:
    MISP_API_KEY = open(os.path.join(os.environ['HOME'], '.misp_api_key')).read().strip()
except IOError:
    MISP_API_KEY = 'abcdefghighklmnopqrst'

MISP_SSL_CHAIN = '/etc/ssl/certs/ca-certificates.crt'

# To remove this deprecation warning:
# SecurityWarning: Certificate has no `subjectAltName`, falling back to check
# for a `commonName` for now. This feature is being removed by major browsers
# and deprecated by RFC 2818. (See https://github.com/shazow/urllib3/issues/497
# for details.)
requests.packages.urllib3.disable_warnings()

class MispBaseObject(object):
    """
    Inherited module regrouping shared variables.

    """
    def __init__(self):
        self._uuid = None
        self._timestamp = None
        self._comment = None
        self._distribution = None
        self._threat_level_id = None
        self._analysis = None

    def to_xml(self):
        obj = self.to_xml_object()
        lxml.objectify.deannotate(obj, xsi_nil=True)
        lxml.etree.cleanup_namespaces(obj)
        return lxml.etree.tostring(obj)

    @property
    def uuid(self):
        return self._uuid

    @uuid.setter
    def uuid(self, value):
        self._uuid = value

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value):
        self._comment = value

    @property
    def timestamp(self):
        if self._timestamp:
            return self._timestamp
        return int(time.time())

    @timestamp.setter
    def timestamp(self, value):
        val = None
        if type(value) is int or type(value) is objectify.IntElement:
            val = int(value)
        elif type(value) is datetime.datetime:
            val = int(time.mktime(value.timetuple()))
        else:
            raise ValueError('Invalid date type: %s' % type(value))
        self._timestamp = val

    @property
    def distribution(self):
        return self._distribution or 0

    @distribution.setter
    def distribution(self, value):
        if int(value) not in [0, 1, 2, 3, 4, 5]:
            raise ValueError('Invalid distribution value for an attribute')
        self._distribution = value

    @property
    def threat_level_id(self):
        return self._threat_level_id or 1

    @threat_level_id.setter
    def threat_level_id(self, value):
        if int(value) not in [1, 2, 3, 4]:
            raise ValueError('Invalid threat_level_id value for an attribute')
        self._threat_level_id = value

    @property
    def analysis(self):
        return self._analysis or 0

    @analysis.setter
    def analysis(self, value):
        if value and int(value) not in [0, 1, 2]:
            raise ValueError('Invalid analysis value for an attribute')
        self._analysis = value or 0


class MispTag(MispBaseObject):
    """
    Object for handling MISP tags in events
    """
    def __init__(self):
        super(MispTag, self).__init__()
        self._id = None
        self._name = None
        self._colour = None
        self._org_id = None
        self._exportable = None

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if value:
            self._id = int(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if value:
            self._name = value

    @property
    def colour(self):
        return self._colour

    @colour.setter
    def colour(self, value):
        if value:
            self._colour = value

    @property
    def org_id(self):
        return self._org_id

    @org_id.setter
    def org_id(self, value):
        if value is not None:
            self._org_id = int(value)

    @property
    def exportable(self):
        return self._exportable

    @exportable.setter
    def exportable(self, value):
        if value:
            self._exportable = (int(value) == 1)

    @staticmethod
    def from_xml(s):
        """
        Static method converting a serialized XML string into a :class:`MispTag` object.

        :example:

        >>> s = '<Tag><id>3</id><name>TLP:GREEN</name><colour>#04cc18</colour><exportable>1</exportable><org_id>0</org_id></Tag>'
        >>> a = MispTag.from_xml(s)
        >>> type(a)
        <class 'misp.MispTag'>

        """
        attr = objectify.fromstring(s)
        return MispTag.from_xml_object(attr)

    @staticmethod
    def from_xml_object(obj):
        if obj.tag.lower() != 'tag':
            raise ValueError('Invalid Tag XML')
        attr = MispTag()
        for field in ['id', 'name', 'colour', 'exportable', 'org_id']:
            val = getattr(obj, field)
            setattr(attr, field, val)
        return attr


class MispEvent(MispBaseObject):
    class Attributes(object):
        """
        The module that provides glue between :class:`MispEvent` and :class:`MispAttribute`

        """
        def __init__(self, event):
            self.event = event
            self._attributes = []

        def add(self, attr):
            """This function adds an attribute to the current event.

            It takes care of updating Event's timestamp and filling the blanks in
            the attribute object (timestamp, uuid, event id).

            :param attr: a :class:`MispAttribute`'s instance to be added to the Event

            :example:

            >>> new_attr = MispAttribute()
            >>> new_attr.value = 'foobar.com'
            >>> new_attr.category = 'Network activity'
            >>> new_attr.type = 'domain'
            >>> server = MispServer()
            >>> event = server.events.get(12)
            >>> event.attributes.add(new_attr)
            >>> server.events.update(event)

            """
            if type(attr) is not MispAttribute:
                raise ValueError("event.attributes.add() only takes MispAttribute instance")
            self.event.timestamp = datetime.datetime.now()
            if not attr.uuid:
                attr.uuid = uuid.uuid4()
            attr.event_id = self.event.id
            attr.timestamp = self.event.timestamp+1
            self._attributes.append(attr)

        def remove(self, attribute):
            """This function removes an attribute from the current event.

            :param attr: `MispAttribute` to be removed to the Event
            .. todo::
               Implement it.
            """
            raise NotImplementedError('Cannot remove attribute yet')

        def __iter__(self):
            return self._attributes.__iter__()

        def __len__(self):
            return len(self._attributes)

        def set(self, val):
            self._attributes = val

    class Tags(object):
        """
        Module that provides glue between :class:`MispEvent` and :class:`MispTag`

        """
        def __init__(self, event):
            self.event = event
            self._tags = []

        def __iter__(self):
            return self._tags.__iter__()

        def __len__(self):
            return len(self._tags)

        def set(self, val):
            self._tags = val

    def __init__(self):
        super(MispEvent, self).__init__()
        self._id = None
        self._info = None
        self._org = None
        self._orgc = None
        self._publish = None
        self._proposal_email_lock = None
        self._locked = None
        self._date = None
        self._publish_timestamp = None
        self._published = None
        self.attributes = MispEvent.Attributes(self)
        self.tags = MispEvent.Tags(self)
        self.shadowattributes = []

    def __repr__(self):
        return "'%i: %s'" % (self._id, self._info)

    @property
    def attribute_count(self):
        """Read-only variable that counts the number of attributes"""
        return len(self.attributes)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        if value:
            self._id = int(value)

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        self._info = unicode(value)

    @property
    def orgc(self):
        return self._orgc

    @orgc.setter
    def orgc(self, value):
        self._orgc = value

    @property
    def published(self):
        return self._published or 0

    @published.setter
    def published(self, value):
        self._published = value

    @property
    def locked(self):
        return self._locked or 0

    @locked.setter
    def locked(self, value):
        self._locked = value

    @property
    def proposal_email_lock(self):
        return self._proposal_email_lock or 0

    @proposal_email_lock.setter
    def proposal_email_lock(self, value):
        self._proposal_email_lock = value

    @property
    def org(self):
        return self._org or DEFAULT_ORG

    @org.setter
    def org(self, value):
        self._org = value

    @property
    def date(self):
        """
        Getter/setter for the date member.

        The setter can take a string or a :meth:`datetime.datetime` and will do the
        appropriate transformation.

        """
        if self._date:
            return self._date
        return datetime.datetime.now().strftime('%Y-%m-%d')

    @date.setter
    def date(self, value):
        val = None
        if type(value) is str or type(value) is objectify.StringElement:
            val = value
        elif type(value) is datetime.datetime:
            val = value.strftime('%Y-%m-%d')
        else:
            raise ValueError('Invalid date type: %s' % type(value))
        self._date = val

    @property
    def publish_timestamp(self):
        """
        Getter/setter.

        The setter can take an integer (as an epoch timestamp) or a :class:`datetime.datetime`.
        instance.
        """
        if self._publish_timestamp:
            return self._publish_timestamp
        return int(time.time())

    @publish_timestamp.setter
    def publish_timestamp(self, value):
        val = None
        if type(value) is int or  type(value) is objectify.IntElement:
            val = value
        elif type(value) is datetime.datetime:
            val = int(time.mktime(value.timetuple()))
        self._publish_timestamp = val

    @staticmethod
    def from_xml(s):
        """
        Static method converting a serialized XML string into a :class:`MispEvent` object.

        :example:

        >>> s = '<Event><id>42</id><Org><name>ACME and bro.<name><uuid>564d9146-2c34-43df-906a-7bc40a3ac101</uuid><id>12</id></Org><Orgc><name>ACME and bro bis.<name><uuid>164d9146-2c34-43df-906a-7bc40a3ac101</uuid><id>13</id></Orgc><date>2015-10-20</date><threat_level_id>3</threat_level_id><info>AGNOSTIC PANDA</info><published>1</published><uuid>56278fd8-f2c0-4907-bcca-594e0a3ac101</uuid><attribute_count>8</attribute_count><analysis>2</analysis><timestamp>1445434988</timestamp><distribution>1</distribution><publish_timestamp>1445435155</publish_timestamp></Event>'
        >>> m = MispEvent.from_xml(s)
        >>> type(m)
        <class 'misp.MispEvent'>
        """
        event = objectify.fromstring(s)
        return MispEvent.from_xml_object(event)

    @staticmethod
    def from_xml_object(obj):
        if obj.tag.lower() != 'event':
            raise ValueError('Invalid Event XML')

        event = MispEvent()
        for field in ['uuid', 'distribution', 'threat_level_id',
                      'date', 'info', 'published', 'analysis',
                      'timestamp', 'distribution', 'publish_timestamp', 'id']:
            val = getattr(obj, field)
            setattr(event, field, val)

        #FIXME: this except catch a lot of unknown bugs
        try:
            attributes = []
            for attr in obj.Attribute:
                attr_obj = MispAttribute.from_xml_object(attr)
                attributes.append(attr_obj)
            event.attributes.set(attributes)
        except:
            # No attribute, no worries
            pass

        try:
            tags = []
            for tag in obj.Tag:
                tag_obj = MispTag.from_xml_object(tag)
                tags.append(tag_obj)
                event.tags.set(tags)
        except AttributeError:
            # No tags
            pass

        try:
            event.org = obj.Org.name
            event.orgc = obj.Orgc.name
        except Exception as err:
            pass

        if hasattr(obj, 'ShadowAttribute'):
            for shadowattribute in obj.ShadowAttribute:
                shadowattribute_obj = MispShadowAttribute.from_xml_object(shadowattribute)
                event.shadowattributes.append(shadowattribute_obj)

        return event

    def to_xml_object(self):
        event = objectify.Element('Event')
        for field in ['uuid', 'distribution', 'threat_level_id', 'org',
                      'orgc', 'date', 'info', 'published', 'analysis',
                      'timestamp', 'distribution', 'proposal_email_lock',
                      'locked', 'publish_timestamp', 'id', 'attribute_count']:
            val = getattr(self, field)
            setattr(event, field, val)
        try:
            for shadowattribute in event.shadowattributes:
                event.append(shadowattribute.to_xml_object())
        except Exception:
            pass
        for attr in self.attributes:
            event.append(attr.to_xml_object())

        org = objectify.Element('Org')
        org.name = self.org
        event.append(org)

        orgc = objectify.Element('Orgc')
        orgc.name = self.orgc
        event.append(orgc)

        return event


class MispTransportError(Exception):
    pass


class MispServer(object):
    """
    Module to communicate with the MISP instance.

   :members:

   .. automethod:: __init__
    """
    def __init__(self, url=DEFAULT_MISP_URL, apikey=MISP_API_KEY, ssl_chain=MISP_API_KEY):
        """Initializes a MispServer instance.

          :param url: Fully qualified URL to the MISP instance
          :param apikey: MISP API key
          :param ssl_chain: SSL certificate chain

        """
        self.url = url
        self.headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml',
            'Authorization': apikey,
        }
        self.events = MispServer.Events(self)
        self.attributes = MispServer.Attributes(self)
        self.shadowattributes = MispServer.ShadowAttributes(self)
        self.verify_ssl = ssl_chain

    def _absolute_url(self, path):
        return self.url + path

    def POST(self, path, body):
        """
        Raw POST to the MISP server

        :param path: URL fragment (ie /events/)
        :param body: HTTP Body (raw bytes)
        :returns: HTTP raw content (as seen by :class:`requests.Response`)
        """
        url = self._absolute_url(path)
        resp = requests.post(url, data=body, headers=self.headers, verify=self.verify_ssl)
        if resp.status_code != 200:
            raise MispTransportError('POST %s: returned status=%d', path, resp.status_code)
        return resp.content

    def GET(self, path):
        """
        Raw GET to the MISP server

        :param path: URL fragment (ie /events/)
        :returns: HTTP raw content (as seen by :class:`requests.Response`)
        """
        url = self._absolute_url(path)
        resp = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if resp.status_code != 200:
            raise MispTransportError('GET %s: returned status=%d', path, resp.status_code)
        return resp.content

    def download(self, attr):
        """
        Download an attribute attachment
        (if type is malware-sample or attachment only)
        :param attr: attribute (should be MispAttribute instance)
        :returns: value of the attachment
        """
        if attr.type not in ['malware-sample', 'attachment']:
            raise ValueError('Only malware-sample and attachment can be downloaded')

        return self.GET('/attributes/downloadAttachment/download/%i' % attr.id)

    class ShadowAttributes(object):
        """
        This module communicates shadow attributes with the MISP server
        """

        def __init__(self, server):
            self.server = server

        def get(self, shadowattributeid):
            """
            Fetches a shadow attribute from the MISP server.

            :param shadowattributeid: Shadow attribute id (as an integer)
            :returns: :class:`MispShadowAttribute` object

            """
            raw = self.server.GET('/shadow_attributes/view/%d' % shadowattributeid)
            response = objectify.fromstring(raw)
            return MispShadowAttribute.from_xml_object(response.ShadowAttribute)

        def add(self, event, shadowattribute):
            """
            Adds a shadow attribute to an event and send it to the MISP server.

            :param event: :class:`MispEvent` object to add
            :param shadowattribute: :class:`MispShadowAttribute` object to add
            :returns: The :class:`MispShadowAttribute` object as seen by the server.

            :example:

            >>> proposal = MispShadowAttribute()
            >>> proposal.value = 'foobar.com'
            >>> proposal.category = 'Network activity'
            >>> proposal.type = 'domain'
            >>> server = MispServer()
            >>> event = server.events.get(12)
            >>> event.attributes.add(new_attr)
            >>> server.shadowattributes.add(event, proposal)

            """

            assert shadowattribute is not MispShadowAttribute
            assert event is not MispEvent
            raw = shadowattribute.to_xml()
            raw = self.server.POST('/shadow_attributes/add/%d' % event.id, raw)
            response = objectify.fromstring(raw)
            return MispShadowAttribute.from_xml_object(response.ShadowAttribute)

        def update(self, attr):
            """
            Updates a shadow attribute on the MISP server.

            :param shadowattribute: :class:`MispShadowAttribute` object to update
            :returns: The :class:`MispShadowAttribute` object as seen by the server.

            :example:

            >>> server = MispServer()
            >>> proposal = server.shadowattributes.get(12)
            >>> proposal.to_ids = 0
            >>> server.shadowattributes.update(proposal)

            """
            assert attr is not MispShadowAttribute
            raw = attr.to_xml()
            raw = self.server.POST('/shadow_attributes/edit/%d' % attr.id, raw)
            response = objectify.fromstring(raw)
            return MispShadowAttribute.from_xml_object(response.ShadowAttribute)

        def accept(self, shadowattribute):
            """
            Accepts a shadow attribute on the MISP server.

            :param shadowattribute: :class:`MispShadowAttribute` object to accept

            :example:

            >>> server = MispServer()
            >>> proposal = server.shadowattributes.get(12)
            >>> server.shadowattributes.accept(proposal)

            """
            assert shadowattribute is not MispShadowAttribute
            raw = self.server.POST('/shadow_attributes/accept/%d' % shadowattribute.id, '')

        def discard(self, shadowattribute):
            """
            Discards a shadow attribute on the MISP server.

            :param shadowattribute: :class:`MispShadowAttribute` object to discard

            :example:

            >>> server = MispServer()
            >>> proposal = server.shadowattributes.get(12)
            >>> server.shadowattributes.discard(proposal)

            """
            assert shadowattribute is not MispShadowAttribute
            self.server.POST('/shadow_attributes/discard/%d' % shadowattribute.id, '')

    class Attributes(object):
        """
        This modules communicates Attributes with the MISP server.
        """
        def __init__(self, server):
            self.server = server

        def get(self, id):
            """
            Fetches an attribute from the MISP server.

            :param id: Attribute id (as an integer)
            :returns: :class:`MispAttribute` object

            """
            response = self.server.GET('/attributes/%d' % id)
            response = objectify.fromstring(raw)
            return MispAttribute.from_xml_object(response.Attribute)

        def update(self, attr):
            """
            Updates an attribute on the MISP server.

            :param attr: :class:`MispAttribute` object to update

            :example:

            >>> server = MispServer()
            >>> attr = server.attributes.get(12)
            >>> attr.comment = 'foobar'
            >>> server.attributes.update(attr)

            """
            assert attr is not MispAttribute
            attr.timestamp = datetime.datetime.now()
            raw = attr.to_xml()
            raw = self.server.POST('/attributes/%d' % attr.id, raw)

        def search(self, value=None, type=None, category=None, tag=None, fromd=None, tod=None, last=None):
            """
            Searches an attribute on the MISP server

            :param value: value of the attribute to be searched (as a string)
            :param type: Type of the attribute to be searched (as a string)
            :param category: Category of the attribute to be searched (as a string)
            :param tag: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'. You can also chain several tag commands together with the '&&' operator. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead).
            :param fromd: Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.
            :param tod: Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.
            :param last: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.
            .. todo:: support by type/category/tags

            :example:
            >>> server = MispServer()
            >>> attr = server.attributes.search("google.com")
            [MispEvent, MispEvent...]

            """
            request = objectify.Element('request')
            if value:
                request.value = value
            if type:
                request.type = type
            if category:
                request.category = category
            if tag:
                request.tag = tag
            if fromd:
                #Dirty trick to have a from tag
                setattr(request, "from", fromd)
            if tod:
                request.to = tod
            if last:
                request.last = last

            lxml.objectify.deannotate(request, xsi_nil=True)
            lxml.etree.cleanup_namespaces(request)
            raw = lxml.etree.tostring(request)
            print(raw)

            try:
                raw = self.server.POST(
                        '/events/restSearch/download',
                        raw
                )
            except MispTransportError as err:
                if err[2] == 404:
                    # 404 not found
                    return []
                else:
                    # Other problem keep the exception
                    raise err
            response = objectify.fromstring(raw)
            events = []
            for evtobj in response.Event:
                events.append(MispEvent.from_xml_object(evtobj))
            return events

    class Events(object):
        """
        This modules communicates Events with the MISP server.
        """

        def __init__(self, server):
            self.server = server

        def get(self, evtid):
            """Fetches an event from the MISP server.

            :param evtid: Event ID (as an integer)
            :returns: :class:`MispEvent` object

            >>> server = MispServer()
            >>> event = server.events.get(12)

            """
            raw_evt = self.server.GET('/events/%d' % evtid)
            response = objectify.fromstring(raw_evt)
            return MispEvent.from_xml_object(response.Event)

        def update(self, event):
            """Modifies an event and propagate a change to the MISP server.

            It will update the event's timestamp and reset the publishing state
            (set to false).

            :param event: The modified :class:`MispEvent` object

            >>> server = MispServer()
            >>> event = server.events.get(12)
            >>> event.distribution = 2
            >>> server.events.update(event)

            """
            event.timestamp = datetime.datetime.now()
            event.published=0
            raw_evt = event.to_xml()
            self.server.POST('/events/%d' % event.id, raw_evt)

        def put(self, event):
            """Creates an event on the MISP server.

            It will find an Event ID for you.

            :param event: The :class:`MispEvent` object to push

            """
            if not event.id:
                lastevent = self.last()
                event.id = lastevent.id+1 # XXX: race-condition possible
            raw_evt = event.to_xml()
            self.server.POST('/events', raw_evt)

        def last(self):
            """Returns the last event published on the MISP server.

            :returns: Last :class:`MispEvent` object published
            """
            return self.list(limit=1, direction='desc')[0]

        def list(self, limit=10, sort='date', direction='asc'):
            """List events on the MISP servers according to the given criteria.

            :param limit: Maximum number of events to fetch
            :param sort: Sorting criteria (can be: date)
            :returns: Last :class:`MispEvent` object published
            """
            url = '/events/index/sort:%s/direction:%s/limit:%d' % (sort, direction, limit)
            raw = self.server.GET(url)
            response = objectify.fromstring(raw)
            events = []
            for evtobj in response.Event:
                events.append(MispEvent.from_xml_object(evtobj))
            return events

        def search(self, attr_type=None, tags=None, value=None,
                  category=None, org=None, date_from=None, date_to=None,
                  last=None, quickfilter=None, evtid=None):
            """Search events on the MISP server.

            Searching criteria:

            :param attr_type: The attribute type, any valid MISP attribute type is accepted.
            :param tags: To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a '!'. You can also chain several tag commands together with the '&&' operator. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead).
            :param value: Search for the given value in the attributes' value field.
            :param category: The attribute category, any valid MISP attribute category is accepted.
            :param org: Search by the creator organisation by supplying the organisation idenfitier.
            :param date_from: Events with the date set to a date after the one specified in the from field (format: 2015-02-15)
            :param date_to: Events with the date set to a date before the one specified in the to field (format: 2015-02-15)
            :param last: Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m)
            :param quickfilter: Enabling this (by passing "1" as the argument) will make the search ignore all of the other arguments, except for the auth key and value.
            :param evtid:
            :returns: List of :class:`MispEvent` objects
            """
            request = objectify.Element('request')
            #request.searchall = 1
            if attr_type:
                request.type = attr_type
            if evtid:
                request.evtid = evtid
            if tags:
                request.tags = tags
            if value:
                request.value = value
            if category:
                request.category = category
            if org:
                request.org = org
            if date_to:
                request.date_to = date_to
            if date_from:
                request.date_from = date_from
            if last:
                request.last = last
            if quickfilter:
                request.quickfilter = quickfilter

            lxml.objectify.deannotate(request, xsi_nil=True)
            lxml.etree.cleanup_namespaces(request)
            raw = lxml.etree.tostring(request)
            raw = self.server.POST('/events/restSearch/download', raw)
            response = objectify.fromstring(raw)
            events = []
            for evtobj in response.Event:
                events.append(MispEvent.from_xml_object(evtobj))
            return events


attr_categories = ['Internal reference', 'Targeting data', 'Antivirus detection',
           'Payload delivery', 'Payload installation', 'Artifacts dropped',
           'Persistence mechanism', 'Network activity', 'Payload type',
           'Attribution', 'External analysis', 'Other', 'Advisory PDF',
           'Advisory YAML', 'Financial fraud' ]

attr_types = ['md5', 'sha1', 'sha256', 'filename', 'pdb',
            'filename|md5', 'filename|sha1', 'filename|sha256', 'ip-src',
            'ip-dst', 'hostname', 'domain', 'domain|ip', 'email-src', 'email-dst',
            'email-subject', 'email-attachment', 'url', 'http-method', 'user-agent',
            'regkey', 'regkey|value', 'AS', 'snort', 'pattern-in-file',
            'pattern-in-traffic', 'pattern-in-memory', 'yara', 'vulnerability',
            'attachment', 'malware-sample', 'link', 'comment', 'text', 'other',
            'named pipe', 'mutex', 'target-user', 'target-email', 'target-machine',
            'target-org', 'target-location', 'target-external', 'btc', 'iban',
            'bic', 'bank-account-nr', 'aba-rtn', 'bin', 'cc-number', 'prtn',
            'threat-actor', 'campaign-name', 'campaign-id', 'malware-type',
            'uri', 'authentihash', 'ssdeep', 'imphash', 'pehash', 'sha224',
            'sha384', 'sha512', 'sha512/224', 'sha512/256', 'tlsh',
            'filename|authentihash', 'filename|ssdeep', 'filename|imphash',
            'filename|pehash', 'filename|sha224', 'filename|sha384',
            'filename|sha512', 'filename|sha512/224', 'filename|sha512/256',
            'filename|tlsh', 'windows-scheduled-task', 'windows-service-name',
            'windows-service-displayname', 'whois-registrant-email',
            'whois-registrant-phone', 'whois-registrant-name', 'whois-registrar',
            'whois-creation-date', 'targeted-threat-index', 'mailslot', 'pipe',
            'ssl-cert-attributes', 'x509-fingerprint-sha1', 'ip-dst|port']

class MispAttribute(MispBaseObject):
    def __init__(self):
        super(MispAttribute, self).__init__()
        self._value = None
        self._category = None
        self._type = None
        self._comment = None
        self._to_ids = None
        self._ShadowAttribute = None
        self._id = None
        self._event_id = None

    @property
    def id(self):
        return self._id or 0

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def comment(self):
        return self._comment or ''

    @comment.setter
    def comment(self, value):
        self._comment = value

    @property
    def event_id(self):
        return self._event_id

    @event_id.setter
    def event_id(self, value):
        self._event_id = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        """The value of the IOC.

        .. todo::
           Note that no check is performed on the format of this value, we delegate this
           verification to the MISP server.
        """
        self._value = value

    @property
    def category(self):
        return self._category

    @category.setter
    def category(self, value):
        if value not in attr_categories:
            raise ValueError('Invalid category for an attribute')
        self._category = value

    @property
    def type(self):
        """Getter/setter

        The setter will verify that the given value is valid.
        """
        return self._type

    @type.setter
    def type(self, value):
        if value not in attr_types:
            raise ValueError('Invalid type for an attribute')
        self._type = value

    @property
    def to_ids(self):
        """Boolean variable
        """
        return self._to_ids or 0

    @to_ids.setter
    def to_ids(self, value):
        self._to_ids = int(value)

    @property
    def ShadowAttribute(self):
        return None

    @staticmethod
    def from_xml(s):
        """
        Static method converting a serialized XML string into a :class:`MispAttribute` object.

        :example:

        >>> s = '<Attribute><id>87183</id><type>regkey|value</type><category>Persistencemechanism</category><to_ids>1</to_ids><uuid>562795f9-5723-4b96-8940-599b0a3ac101</uuid><event_id>486</event_id><distribution>1</distribution><timestamp>1445434872</timestamp><comment>loooool</comment><value>lol</value><ShadowAttribute/></Attribute>'
        >>> a = MispAttribute.from_xml(s)
        >>> type(a)
        <class 'misp.MispAttribute'>

        """
        attr = objectify.fromstring(s)
        return MispAttribute.from_xml_object(attr)

    @staticmethod
    def from_xml_object(obj):
        if obj.tag.lower() != 'attribute':
            raise ValueError('Invalid Attribute XML')
        attr = MispAttribute()
        for field in ['uuid', 'distribution', 'type', 'category',
                      'timestamp', 'to_ids', 'comment', 'value',
                      'event_id', 'id']:
            val = getattr(obj, field)
            setattr(attr, field, val)
        return attr

    def to_xml_object(self):
        attr = objectify.Element('Attribute')
        for field in ['distribution', 'type', 'category',
                      'to_ids', 'comment', 'value',
                      'event_id', 'timestamp', 'uuid', 'id']:
            val = getattr(self, field)
            setattr(attr, field, val)
        return attr


class MispShadowAttribute(MispAttribute):
    """A shadow attribute is what human beings call proposal :)

       It is the same thing than a :class:`MispAttribute`. This module basically
       inherits everything from it.

    """
    def __init__(self):
        super(MispShadowAttribute, self).__init__()

    @staticmethod
    def from_xml(s):
        """
        Static method converting a serialized XML string into a :class:`MispShadowAttribute` object.

        :example:

        >>> s = '<ShadowAttribute>...</ShadowAttribute>
        >>> a = MispShadowAttribute.from_xml(s)
        >>> type(a)
        <class 'misp.MispShadowAttribute'>
        """
        attr = objectify.fromstring(s)
        return MispShadowAttribute.from_xml_object(attr)

    @staticmethod
    def from_attribute(attr):
        """
        Converts an attribute into a shadow attribute.

        :param attr: :class:`MispAttribute` instance to be converted
        :returns: Converted :class:`MispShadowAttribute`
        :example:

        >>> server = MispServer()
        >>> event = server.events.get(12)
        >>> attr = event.attributes[0]
        >>> prop = MispShadowAttribute.from_attribute(attr)

        """
        assert attr is not MispAttribute
        prop = MispShadowAttribute()
        prop.distribution = attr.distribution
        prop.type = attr.type
        prop.comment = attr.comment
        prop.value = attr.value
        prop.category = attr.category
        prop.to_ids = attr.to_ids
        return prop

    @staticmethod
    def from_xml_object(obj):
        if obj.tag.lower() != 'shadowattribute':
            raise ValueError('Invalid ShadowAttribute XML (tag="%s")' % obj.tag.lower())
        shadowattribute = MispShadowAttribute()
        for field in ['type', 'category', 'to_ids', 'comment', 'value', 'id']:
            try:
                val = getattr(obj, field)
                setattr(shadowattribute, field, val)
            except AttributeError:
                pass
        return shadowattribute

    def to_xml_object(self):
        attr = objectify.Element('ShadowAttribute')
        for field in ['type', 'category', 'to_ids', 'comment', 'value']:
            val = getattr(self, field)
            setattr(attr, field, val)
        return attr

