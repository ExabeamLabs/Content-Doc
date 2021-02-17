#### Parser Content
```Java
{
Name = cisco-dns-response-1
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = Syslog
  DataType = "dns-response"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Skyformation""", """"src-endpoint":"DNS"""", """"src-application-name":"Cisco Umbrella"""", """"action":""", """"queryType":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"mostGranularIdentity":"({host}[^"]+)"""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"responseCode":"({dns_response_code}[^"]+)"""",
    """"action":"({outcome}[^"]+)"""",
    """"queryType":"({query_type}[^"]+)"""",
    """"domain":"({query}[^"]+)"""",
    """"domain":"({query}[^"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""",
    """"categories":\[(|""|({categories}[^\]]+))\]""",
    """"categories":\["({category}[^"]+)"""",
    """"internalIp":"({dest_ip}[a-fA-F:\d.]+)""",
    """"externalIp":"({src_ip}[a-fA-F:\d.]+)""",
    """"identities":\[({identities}[^\[\]]+)\]""",
    """src-account-name":"({account_name}[^"]+)"""
  ]
  DupFields = [ "host->src_host" ]
}
```