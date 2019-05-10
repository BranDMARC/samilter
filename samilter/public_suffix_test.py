# coding: utf-8
import sys
import os
from . import dmarc

# https://raw.githubusercontent.com/publicsuffix/list/master/tests/test_psl.txt
#
# put Public Suffix List
# pytest / pytest -v

pslFile = "./public_suffix_list.dat"
psl = dmarc.PublicSuffixList(pslFile)

def checkPublicSuffix(domain, expect):
  assert psl.get_org_domain(domain) == expect


null = None
## null input.
def test_null():
  checkPublicSuffix(null, null);

## Mixed case.
def test_mixed_01():
  checkPublicSuffix('COM', null);
def test_mixed_02():
  checkPublicSuffix('example.COM', 'example.com');
def test_mised_03():
  checkPublicSuffix('WwW.example.COM', 'example.com');

## Leading dot.
def test_dot_01():
  checkPublicSuffix('.com', null);
def test_dot_02():
  checkPublicSuffix('.example', null);
def test_dot_03():
  checkPublicSuffix('.example.com', null);
def test_dot_04():
  checkPublicSuffix('.example.example', null);

## Unlisted TLD.
def test_unlisted_01():
  checkPublicSuffix('example', null);
def test_unlisted_02():
  checkPublicSuffix('example.example', 'example.example');
def test_unlisted_03():
  checkPublicSuffix('b.example.example', 'example.example');
def test_unlisted_04():
  checkPublicSuffix('a.b.example.example', 'example.example');

## Listed, but non-Internet, TLD.
#def test_local_01():
#  checkPublicSuffix('local', null);
#def test_local_02():
#  checkPublicSuffix('example.local', null);
#def test_local_03():
#  checkPublicSuffix('b.example.local', null);
#def test_local_04():
#  checkPublicSuffix('a.b.example.local', null);

## TLD with only 1 rule.
def test_tld1_01():
  checkPublicSuffix('biz', null);
def test_tld1_02():
  checkPublicSuffix('domain.biz', 'domain.biz');
def test_tld1_03():
  checkPublicSuffix('b.domain.biz', 'domain.biz');
def test_tld1_04():
  checkPublicSuffix('a.b.domain.biz', 'domain.biz');

## TLD with some 2-level rules.
def test_tld2_01():
  checkPublicSuffix('com', null);
def test_tld2_02():
  checkPublicSuffix('example.com', 'example.com');
def test_tld2_03():
  checkPublicSuffix('b.example.com', 'example.com');
def test_tld2_04():
  checkPublicSuffix('a.b.example.com', 'example.com');
def test_tld2_05():
  checkPublicSuffix('uk.com', null);
def test_tld2_06():
  checkPublicSuffix('example.uk.com', 'example.uk.com');
def test_tld2_07():
  checkPublicSuffix('b.example.uk.com', 'example.uk.com');
def test_tld2_08():
  checkPublicSuffix('a.b.example.uk.com', 'example.uk.com');
def test_tld2_09():
  checkPublicSuffix('test.ac', 'test.ac');
  
## TLD with only 1 (wildcard) rule.
def test_tld1_wild_01():
  checkPublicSuffix('mm', null);
def test_tld1_wild_02():
  checkPublicSuffix('c.mm', null);
def test_tld1_wild_03():
  checkPublicSuffix('b.c.mm', 'b.c.mm');
def test_tld1_wild_04():
  checkPublicSuffix('a.b.c.mm', 'b.c.mm');

## More complex TLD.
def test_complex_01():
  checkPublicSuffix('jp', null);
def test_complex_02():
  checkPublicSuffix('test.jp', 'test.jp');
def test_complex_03():
  checkPublicSuffix('www.test.jp', 'test.jp');
def test_complex_04():
  checkPublicSuffix('ac.jp', null);
def test_complex_05():
  checkPublicSuffix('test.ac.jp', 'test.ac.jp');
def test_complex_06():
  checkPublicSuffix('www.test.ac.jp', 'test.ac.jp');
def test_complex_07():
  checkPublicSuffix('kyoto.jp', null);
def test_complex_08():
  checkPublicSuffix('test.kyoto.jp', 'test.kyoto.jp');
def test_complex_09():
  checkPublicSuffix('ide.kyoto.jp', null);
def test_complex_10():
  checkPublicSuffix('b.ide.kyoto.jp', 'b.ide.kyoto.jp');
def test_complex_11():
  checkPublicSuffix('a.b.ide.kyoto.jp', 'b.ide.kyoto.jp');
def test_complex_12():
  checkPublicSuffix('c.kobe.jp', null);
def test_complex_13():
  checkPublicSuffix('b.c.kobe.jp', 'b.c.kobe.jp');
def test_complex_14():
  checkPublicSuffix('a.b.c.kobe.jp', 'b.c.kobe.jp');
def test_complex_15():
  checkPublicSuffix('city.kobe.jp', 'city.kobe.jp');
def test_complex_16():
  checkPublicSuffix('www.city.kobe.jp', 'city.kobe.jp');

## TLD with a wildcard rule and exceptions.
def test_tld_wild_01():
  checkPublicSuffix('ck', null);
def test_tld_wild_02():
  checkPublicSuffix('test.ck', null);
def test_tld_wild_03():
  checkPublicSuffix('b.test.ck', 'b.test.ck');
def test_tld_wild_04():
  checkPublicSuffix('a.b.test.ck', 'b.test.ck');
def test_tld_wild_05():
  checkPublicSuffix('www.ck', 'www.ck');
def test_tld_wild_06():
  checkPublicSuffix('www.www.ck', 'www.ck');

## US K12.
def test_us_k12_01():
  checkPublicSuffix('us', null);
def test_us_k12_02():
  checkPublicSuffix('test.us', 'test.us');
def test_us_k12_03():
  checkPublicSuffix('www.test.us', 'test.us');
def test_us_k12_04():
  checkPublicSuffix('ak.us', null);
def test_us_k12_05():
  checkPublicSuffix('test.ak.us', 'test.ak.us');
def test_us_k12_06():
  checkPublicSuffix('www.test.ak.us', 'test.ak.us');
def test_us_k12_07():
  checkPublicSuffix('k12.ak.us', null);
def test_us_k12_08():
  checkPublicSuffix('test.k12.ak.us', 'test.k12.ak.us');
def test_us_k12_09():
  checkPublicSuffix('www.test.k12.ak.us', 'test.k12.ak.us');

## IDN labels.
#def test_idn_01():
#  checkPublicSuffix('食狮.com.cn', '食狮.com.cn');
#def test_idn_02():
#  checkPublicSuffix('食狮.公司.cn', '食狮.公司.cn');
#def test_idn_03():
#  checkPublicSuffix('www.食狮.公司.cn', '食狮.公司.cn');
#def test_idn_04():
#  checkPublicSuffix('shishi.公司.cn', 'shishi.公司.cn');
#def test_idn_05():
#  checkPublicSuffix('公司.cn', null);
#def test_idn_06():
#  checkPublicSuffix('食狮.中国', '食狮.中国');
#def test_idn_07():
#  checkPublicSuffix('www.食狮.中国', '食狮.中国');
#def test_idn_08():
#  checkPublicSuffix('shishi.中国', 'shishi.中国');
#def test_idn_09():
#  checkPublicSuffix('中国', null);

## Same as above, but punycoded.
def test_puny_01():
  checkPublicSuffix('xn--85x722f.com.cn', 'xn--85x722f.com.cn');
def test_puny_02():
  checkPublicSuffix('xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn');
def test_puny_03():
  checkPublicSuffix('www.xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn');
def test_puny_04():
  checkPublicSuffix('shishi.xn--55qx5d.cn', 'shishi.xn--55qx5d.cn');
def test_puny_05():
  checkPublicSuffix('xn--55qx5d.cn', null);
def test_puny_06():
  checkPublicSuffix('xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s');
def test_puny_07():
  checkPublicSuffix('www.xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s');
def test_puny_08():
  checkPublicSuffix('shishi.xn--fiqs8s', 'shishi.xn--fiqs8s');
def test_puny_09():
  checkPublicSuffix('xn--fiqs8s', null);








