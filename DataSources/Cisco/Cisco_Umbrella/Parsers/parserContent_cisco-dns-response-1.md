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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"mostGranularIdentity":"({host}[^"]{1,2000})"""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"responseCode":"({dns_response_code}[^"]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"queryType":"({query_type}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))"""",
    """"categories":\[(|""|({categories}[^\]]{1,2000}))\]""",
    """"categories":\["({category}[^"]{1,2000})"""",
    """"internalIp":"({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"externalIp":"({src_ip}[a-fA-F:\d.]{1,2000})""",
    """"identities":\[({identities}[^\[\]]{1,2000})\]""",
    """src-account-name":"({account_name}[^"]{1,2000})"""
  ]
  DupFields = [ "host->src_host" ]
}
```