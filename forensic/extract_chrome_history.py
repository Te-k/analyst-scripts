import argparse
import sqlite3
import csv
from datetime import datetime

"""
Schema
CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);
CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER NOT NULL,visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL,incremented_omnibox_typed_score BOOLEAN DEFAULT FALSE NOT NULL);
"""

def convert_timestamp(tmstp):
    return datetime.fromtimestamp(int(tmstp)/ 1000000 - 11644473600)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('FILE', help='History file')
    parser.add_argument('--filter', '-f', help='Filter on the url')
    args = parser.parse_args()


    query = "SELECT urls.id, urls.url, urls.title, urls.visit_count, urls.typed_count, urls.last_visit_time, urls.hidden, visits.visit_time, visits.from_visit, visits.visit_duration, visits.transition, visit_source.source FROM urls JOIN visits ON urls.id = visits.url LEFT JOIN visit_source ON visits.id = visit_source.id"
    if args.filter:
        query += ' WHERE urls.url like "%{}%"'.format(args.filter)
    query += " ORDER BY visits.visit_time;"

    conn = sqlite3.connect(args.FILE)
    c = conn.cursor()


    print("url_id,url,title,#visits,typed_count,last_visit_time,hidden,visit_time,from_visit,visit_duration,transition,source")
    for row in c.execute(query):
        print("{},{},\"{}\",{},{},{},{},{},{},{},{},{}".format(
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            convert_timestamp(row[5]).strftime("%Y-%m-%d %H:%M:%S:%f"),
            row[6],
            convert_timestamp(row[7]).strftime("%Y-%m-%d %H:%M:%S:%f"),
            row[8],
            row[9],
            row[10],
            row[11]
        ))
