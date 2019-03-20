#! /usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017, S.Sakuraba, All rights reserved.
#
import sys
import os
import DNS

__version__ = '0.2.4'

# ------------------------------- #
# --- public suffix list data --- #
# ------------------------------- #
class PublicSuffixList():

    def __init__(self, fname):
        self.publicsuffix = None
        self.wildcardsuffix = None
        self.exclamationsuffix = None

        if not os.path.exists(fname):
            #syslog.syslog('* Error: Suffix file ({}) not found'.format(fname))
            return None
        self.publicsuffix = []
        self.wildcardsuffix = []
        self.exclamationsuffix = []
        # prepare public suffix list dictionary
        for l in open(fname, 'r').readlines():
            line = l.strip()
            if len(line) == 0:
                continue
            if line[0] == '/' and line[1] == '/':
                continue
            # check wildcard rule
            if line[0] == '*' and line[1] == '.':
                self.store_item(line[2:], self.wildcardsuffix)
            # check eclamation rule
            elif line[0] == '!':
                self.store_item(line[1:], self.exclamationsuffix)
            else:
                # check internationalization domain (UTF-8)
                if not all([ord(c)>=ord('-') and ord(c)<=ord('z')  for c in line]):
                    domsuffix = unicode(line, 'utf-8').encode('idna')
                else:
                    domsuffix = line
                self.store_item(domsuffix, self.publicsuffix)
        #return None

    def store_item(self, name, container):
        if not name in container:
            container.append(name)

    def get_org_domain(self, domain):
        if self.publicsuffix == None:
            return None
        labels= domain.split('.')
        length = len(labels)
        for index in range(length):
            orgdom = '.'.join(labels[index:])
            if orgdom in self.exclamationsuffix:
                break
            if orgdom in self.wildcardsuffix:
                index = index - 2
                break
            if orgdom in self.publicsuffix:
                index = index - 1
                break
        if index > 0:
            return '.'.join(labels[index:])
        return None
        

# ---------------------------- #
# --- DMARC authentication --- #
# ---------------------------- #
class domain():
    headerdomain = None
    publicsuffix = None
    dnstimeout = 20
    discoverNS = False

    def __init__(self, dname, pbl):
        if dname == None:
            return None
        self.publicsuffix = pbl
        self.headerdomain = dname
        self.orgdomain = pbl.get_org_domain(self.headerdomain)
        
    def lookup_dns(self, domain):
        if not self.discoverNS:
            DNS.DiscoverNameServers()
            self.discoverNS = True
        name = '_dmarc.' + domain
        try:
            req = DNS.DnsRequest(name=name, qtype=DNS.Type.TXT, timeout=self.dnstimeout)
            res = req.req()
            if res.header['tc'] == True:
                try:
                    req = DNS.DnsRequest(name, qtype='TXT', protocol='tcp', timeout=self.dnstimeout)
                    res = req.req()
                except DNS.DNSError as x:
                    print 'DNS: TCP fallback error:', str(x)
                if res.header['rcode'] != 0 and res.header['rcode'] != 3:
                    print 'DNS Error:', res.header['status'], ' RCODE ({})'.format(res.header['rcode'])
            return [((a['name'], a['typename']), a['data'])
                    for a in res.answers] \
                        + [((a['name'], a['typename']), a['data'])
                           for a in res.additional]
        except AttributeError as x:
            print 'DNS attribute:' + str(x)
        except IOError as x:
            print 'DNS IOE:' + str(x)
        except DNS.DNSError as x:
            'DNS ' + str(x)


    def get_dmarc_alignment(self, record):
        if not record:
            return None
        adkim = True	# means strict (DKIM)
        aspf = True		# means strict (SPF)
        params = record.split(';')
        for p in params:
            param = p.strip()
            if len(param) > 0:
                tag = param.split('=')[0]
                val = param.split('=')[1]
                if tag == 'adkim' and val == 's':
                    adkim = False
                elif tag == 'aspf' and val == 's':
                    aspf = False
        return adkim, aspf

    def get_record(self, domain):
        if not domain:
            return None
        res = self.lookup_dns(domain)
        for r in res:
            record = r[1][0]
            if record[:8] == 'v=DMARC1':
                return record
        return None

    def authenticate(self, spfdomain, dkimdomain):
        drecord = self.get_record(self.headerdomain)
        if not drecord:
            if self.orgdomain:
                drecord = self.pbl.get_dmarcrecord(self.orgdomain)
        if not drecord:
            return 'none'
        if self.headerdomain == spfdomain or self.headerdomain == dkimdomain:
            return 'pass'
        adkim, aspf = self.get_dmarc_alignment(drecord)
        spforgdomain = self.publicsuffix.get_org_domain(spfdomain)
        dkimorgdomain = self.publicsuffix.get_org_domain(dkimdomain)
        if aspf and (self.orgdomain == spforgdomain):
            return 'pass'
        if adkim and (self.orgdomain == spforgdomain):
            return 'pass'
        return 'fail'
