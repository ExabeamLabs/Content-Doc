#### Parser Content
```Java
{
Name = cisco-dns-response-1
  Vendor = Cisco
  Product = Umbrella
  Lms = Syslog
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"src-endpoint":"DNS"""", """"src-application-name":"Cisco Umbrella"""", """"action":""", """"queryType":""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"mostGranularIdentity":"({host}[\w.-]{1,2000})"""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"responseCode":"({dns_response_code}[^"]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"queryType":"({query_type}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{1,2000})"""",
    """"categories":\[(|""|({categories}[^\]]{1,2000}))\]""",
    """"categories":\["({category}[^"]{1,2000})"""",
    """"internalIp":"({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"externalIp":"({src_ip}[a-fA-F:\d.]{1,2000})""",
    """"identities":\[({identities}[^\[\]]{1,2000})\]""",
    """src-account-name":"({account_name}[^"]{1,2000})""",
    """"identities":\["({user_fullname}[^\(\)"]{1,2000}?)(?:\s{0,100}\(\w{1,100}\)\s{0,100})?(\s{1,100}\(({user_email}[^@\(\)"]{1,2000}@[^@"\(\)]{1,2000})\))",("({host}[\w\-\.]{1,2000})")""",
    """"identities":\[("({host}[\w\-\.]{1,2000})"),"({user_fullname}[^\(\)"]{1,2000}?)(?:\s{0,100}\(\w{1,100}\)\s{0,100})?(\s{1,100}\(({user_email}[^@"\(\)]{1,2000}@[^@"\(\)]{1,2000})\))"""",
    """"mostGranularIdentity":"({user_fullname}[^\(\)"]{1,2000}?)(?:\s{0,100}\(\w+\)\s{0,100})?\s{1,100}((\([^\)]{1,2000}\))\s\(|\()({user_email}[^@"\s\(\)]{1,2000}@[^@"\s\(\)]{1,2000})\)""""
  ]
  DupFields = [ "host->src_host" ]


}
```