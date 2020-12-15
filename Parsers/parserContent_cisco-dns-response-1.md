#### Parser Content
```Java
{
Name = cisco-dns-response-1
  Vendor = Cisco
  Product = OpenDNS Umbrella
  Lms = Syslog
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Skyformation""", """"src-endpoint":"DNS"""", """"src-application-name":"Cisco Umbrella"""", """"action":""", """"queryType":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-]+)\s+Skyformation\s""",
    """"mostGranularIdentity":"({host}[^"]+)"""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"responseCode":"({dns_response_code}[^"]+)"""",
    """"action":"({outcome}[^"]+)"""",
    """"queryType":"({query_type}[^"]+)"""",
    """"domain":"({query}[^"]+)"""",
    """"categories":\[(|""|({categories}[^\]]+))\]""",
    """"categories":\["({category}[^"]+)"""",
    """"internalIp":"({dest_ip}[a-fA-F:\d.]+)""",
    """"externalIp":"({src_ip}[a-fA-F:\d.]+)""",
    """"identities":\[({identities}[^\[\]]+)\]"""
  ]
  DupFields = [ "host->src_host" ]
}
```