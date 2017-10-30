#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2015. The Koodous Authors. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

header = \
"""
--------------Koodous Script Manage--------------------
Url:\t\thttps://koodous.com
Twitter:\t@koodous_project
Author:\t\tframirez@koodous.com
\t\t2015
Get your TOKEN --> https://koodous.com/settings/profile

"""

import requests
import json
from os import listdir
from os.path import isfile, join

import urllib
import hashlib
import argparse
import time
import json

class wmup:

    #TOKEN = '****YOUR TOKEN****'
    TOKEN = 'dd739bf8e936383b1c9fc1269b1681891f722ebc'
    URL = 'https://koodous.com/api/%s%s%s'

    def __init__(self, token=None):
        if token is not None:
            self.TOKEN = token
        self.headers = {'Authorization': 'Token %s' % self.TOKEN}
        self.sha256 = ''
        self.l_sha256 = []

    def hash256(self, tfile):
        """
            Generate the hash from file
        """

        f = open(tfile, 'rb')
        fr = f.read()
        hasher_256 = hashlib.sha256()
        hasher_256.update(fr)
        self.sha256 = hasher_256.hexdigest()
        return self.sha256

    def upload(self, ffile):
        """
            Function to upload files
        """

        url = self.URL % ('apks/', self.hash256(ffile), '/get_upload_url')
        r = requests.get(url=url, headers=self.headers)

        if r.status_code == 200:
            j = r.json()
            files = {'file': open(ffile, 'rb')}
            s = requests.post(url=j['upload_url'], files=files)
            return s.status_code
        else:

            return r.status_code
            
    def download(self, sha256, ffile=None):
        """
            Function to download files
        """

        url = self.URL % ('apks/', sha256, '/download')
        r = requests.get(url=url, headers=self.headers)

        if r.status_code is 200:
            j = r.json()
            testfile = urllib.URLopener()
            testfile.retrieve(j['download_url'], ffile)

        return r.status_code
        
    def search_by_file(self, filename):
        '''
        filename contains keywords that you want to search per line
        '''
        with open(filename) as fr:
            for line in fr:
                self.search_koodous_db(line.strip())

    def search_koodous_db(self, term, page=1, page_size=100):
        url = self.URL % ('apks', '?search=%s&page=%i&page_size=%i' % (term, page, page_size), "" )
        r = requests.get(url=url, headers=self.headers)
        self.obj = r.json()
        self.decode_results()
        return r

    def decode_results(self):
        self.l_sha256 = []
        for doc in self.obj['results']:
            self.l_sha256.append(doc['sha256'])
            print('%s\t%s\t%s\t%s'%(doc['sha256'], 
                                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(doc['created_on'])),
                                    doc['app'],
                                    doc['package_name']))
        
    def check_koodous_db(self, hash):
        """
            Function to check if exist in Koodous DB by hash
        """

        r = self.search_koodous_db(hash)
        if r.json().get('count') > 0:
            return 200
        else:
            return 404
       

    def is_apk(self, content):
        """
            Check if a filetype is APK
        """

        zip = zipfile.ZipFile(StringIO.StringIO(content))
        for i in zip.namelist():
            if i == 'AndroidManifest.xml':
                return True

        return False

    def vote_apk(self, sha256, kind):
        """
            Vote apk positive || negative
        """

        url = self.URL % ('apks/', sha256, '/votes')
        return requests.post(url, data={'kind': kind},
                             headers=self.headers)

    def comment_apk(self, sha256, text):
        """
            Comment apks
        """

        url = self.URL % ('apks/', sha256, '/comments')
        return requests.post(url, data={'text': text},
                             headers=self.headers)

    def follow_user(self, username):
        """
            Follow user
        """

        url = self.URL % ('analysts/', username, '/follow')
        return requests.get(url, headers=self.headers)

    def write_tag(self, sha256, tag):
        """
            Write a tag in apk
        """

        url = self.URL % ('apks/', sha256, '/tags')
        return requests.post(url, headers=self.headers,
                             data={'name': tag})

    def read_ruleset_detection(self, ruleset_id, page=1, page_size=10):
        """
            Get the APK mathced with a ruleset
        """
        url = self.URL % ('ruleset_matches/', ruleset_id, '/apks?page=%s&page_size=%s' % (page, page_size))
        return requests.get(url, headers=self.headers)

    def analyze(self, sha256):
        """
            Send to analyze
        """
        url = self.URL % ('apks/', sha256, '/analyze')
        return requests.get(url, headers=self.headers)

    def get_analysis(self, sha256):
        """
            Get the analysis from APK
            #not for CLI
        """
        url = self.URL % ('apks/', sha256, '/analysis')
        return requests.get(url, headers=self.headers)  

    def get_info(self, sha256):
        """
            Get info for apk
        """
        url = self.URL % ('apks/', sha256, '')
        return requests.get(url, headers=self.headers)

    def get_metadata(self, sha256):
        """
            Get metadata for apk
        """
        url = self.URL % ('apks/', sha256, '/metadata')
        return requests.get(url, headers=self.headers)      


if __name__ == '__main__':
    def upload_script(row):
        code = a.upload(row)
        if code is 429:
            print "Sleeping %i seconds for api reached" % 60
            time.sleep(60)
            upload_script(row)
        return code

    def usage():
        print("""
Often Used:
    python pykoodous.py -search com.gw.coreapp  search
    python pykoodous.py -search xx -f t.txt  search
        
    python pykoodous.py -f t.txt download
    python pykoodous.py -s f02fb50da36702c5b8d9a520d60c10e43bfe23b5a182e2e4f3903a2debfbea70 download
        """)
        
    status_response = {
                    200: "All is done",
                    201: "Created",
                    415: "It,s not a apk",
                    412: "Policy exception",
                    408: "The url is lapsed",
                    409: "Apk already exist in our database",
                    401: "Invalid token",
                    429: "Api limit reached",
                    404: "Dont exist"
                    }
    #print header
    parser = \
        argparse.ArgumentParser(description='Script for upload and download files to Koodous') # usage=usage())

    parser.add_argument('action', action='store',
                        help='search | search_by_file | download | download_by_file | upload | checkApk | tag | vote | comment | follow |\
                        check | get_info | get_metadata')
                        
    parser.add_argument('-search', '--search', dest='keywords',
                        help='search by keywords', default=None)
               
    parser.add_argument('-sha1', '--sha1', dest='sha1', help='sha1',
                        default=None)
    parser.add_argument('-m', '--md5', dest='md5', help='md5',
                        default=None)
    parser.add_argument('-s', '--sha256', dest='sha256',
                        help='hash for file', default=None)
     
     
    parser.add_argument('-T', '--token', dest='token', help='token',
                        default=None)
                        
    parser.add_argument('-f', '--file', dest='file', help='filename',
                        default=None)
    parser.add_argument('-p', '--path', dest='path',
                        help='specify the path', default='./')
    
    '''
    parser.add_argument('-k', '--kind', dest='kind_vote',
                        help='kind vote', default=None)
    parser.add_argument('-c', '--comment', dest='comment',
                        help='comment', default=None)
    parser.add_argument('-u', '--username', dest='username',
                        help='username', default=None)
    parser.add_argument('-t', '--tag', dest='tag', help='tag',
                        default=None)
    parser.add_argument('-M', '--magic_word', dest='magic', help='Magic Thrick',
                        default=None)
    '''
    args = parser.parse_args()
    results = parser.parse_args()

    a = wmup(results.token)

    if results.action == 'upload':
        if results.path is not '/tmp/' and results.file is None:
            onlyfiles = [f for f in listdir(results.path)
                         if isfile(join(results.path, f))]

            for row in onlyfiles:
                try:
                    print 'Uploading %s' % (results.path + row)
                    code = upload_script(results.path + row)
                    print status_response[code]

                except Exception, error:
                    print 'Error upload %s' % error
        elif results.file is not None:

            print 'Uploading %s' % results.file
            code = upload_script(results.file)
            print status_response[code]

        else:
            print 'You need specify file to upload [-f] or path [-p]'
    elif results.action == 'download': 
        if results.file:
            with open(results.file) as fr:
                for sha256 in fr:
                    print 'Downloading %s'%sha256
                    a.download(sha256.strip(), sha256.strip())
            exit(-1)
            
        if results.sha256 is not None:
            if results.file is None:
                results.file = results.path + results.sha256
            print 'Downloading %s in %s' % (results.sha256,
                    results.file)
            code = a.download(results.sha256, results.file)
            print status_response[code]

        else:
            print 'You need specify sha256 to download [-s]'
    
    elif results.action == 'checkApk':

        if results.file is not None:
            f = open(results.file, 'rb')
            content = f.read()

            if content[:2] == 'PK':
                if a.is_apk(content):
                    print "It's APK"
                else:
                    print "It's not APK"
    elif results.action == 'vote':

        if results.sha256 is not None and results.kind_vote \
            in ['positive', 'negative']:
            if a.vote_apk(results.sha256,
                          results.kind_vote).status_code in [200, 201]:
                print 'Vote apk %s sucesfully' % results.sha256
        else:
            print 'You need specify sha256 [-s] and vote [-k] (negative || positive) '
    elif results.action == 'comment':

        if results.sha256 is not None and results.comment:
            if a.comment_apk(results.sha256,
                             results.comment).status_code in [200, 201]:
                print 'Comment apk %s sucesfully' % results.sha256
        else:

            print 'You need specify sha256 [-s] and comment [-c]'
    elif results.action == 'follow':

        if results.username:
            if a.follow(results.username).status_code in [200, 201]:
                print 'You follow %s' % results.username
        else:
            print 'You need specify username [-u]'
    elif results.action == 'tag':

        if results.sha256 is not None and results.tag is not None:
            if a.write_tag(results.sha256, results.tag).status_code \
                in [200, 201]:
                print 'Tag %s to %s' % (results.sha256, results.tag)
        else:
            print 'You need specify sha256 [-s] and tag [-t]'

    elif results.action == 'check':

        if results.sha256 is not None:
            print status_response[a.check_koodous_db(results.sha256)]
        elif results.sha1 is not None:
            print status_response[a.check_koodous_db(results.sha1)]
        elif results.md5 is not None:
            print status_response[a.check_koodous_db(results.md5)]

        else:
            print 'you need specify sha256 [-s] or sha1 [-sha1] or md5 [-m]'    

    elif results.action == "search":
        if not results.file:
            a.check_koodous_db(results.keywords)
            exit(-1)
        
        with open(results.file) as fr:
            for keyword in fr:
                a.check_koodous_db(keyword)
        
    elif results.action == 'get_info':
        if results.sha256 is not None:
            if results.magic is not None:
                print a.get_info(results.sha256).json().get(results.magic)
            else:
                print a.get_info(results.sha256).text

    elif results.action == 'get_metadata':
        if results.sha256 is not None:
            if results.magic is not None:
                mt = a.get_metadata(results.sha256)
                if mt.json().get(results.magic):
                    print mt.json().get(results.magic)
                else:
                    for row in mt.json().get('info'):
                        if row.get(results.magic):
                            print row[results.magic]
            else:
                print a.get_metadata(results.sha256).text
