# samilter
Sender Authentication Milter which includes SPF, DKIM and DMARC based on dkimpy-milter.
This package requires thease packages.
- dkimpy-milter
- pymilter
- pyspf
- pydns
- sendmail-milter (pymilter is wrapper of sendmail-milter library)

## configuration
- main config file (/usr/local/etc/senderauth-milter.conf)
- public suffix list file (/usr/local/etc/public_suffix_list.dat)
	- down load from [PUBLIC SUFFIX LIST](https://publicsuffix.org)
- configure DKIM related parametors and setup
	- define selector name and define in main config file (senderauth-milter.conf)
	- generate key pairs (ex. `opendkim-keygen`)
		- put secret at the path of `KeyFile` parameter in main config file
		- put public key to DNS (TXT RR of *<selector>*._domainkey.*<domain>*)
