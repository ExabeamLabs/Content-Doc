#### Parser Content
```Java
{
Name = paloalto-network-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,url,"""]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,url,[^,]{1,2000},({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d),""",
    """THREAT,[^,]{1,2000},[^,]{1,2000},({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z),""",
    """THREAT,url,([^,]{1,2000},){2}({src_ip}[A-Fa-f\d:.]{1,2000}),({dest_ip}[A-Fa-f\d:.]{1,2000}),({src_translated_ip}[A-Fa-f\d:.]{1,2000}),({dest_translated_ip}[A-Fa-f\d:.]{1,2000}),""",
    """THREAT,url,([^,]{0,2000},){26}(\\?"{1,20})?(\w{1,20}:\/{2})?(www\.)?({web_domain}[^,\\?:"]{1,2000}?)[\\\/\s:"]"""
    """THREAT,([^,]{0,2000},){7}({rule}[^,]{1,2000}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){8}(({user_email}[^@,]{1,2000}@[^\.]{1,2000}\.[^,]{1,2000})|(({domain}[^\\]{1,2000}?)[\\]{1,2})?({user}[^,\\\/]{1,2000}))"""
    """THREAT,([^,]{0,2000},){10}(not-applicable|({network_app}[^,]{1,2000}?))\s{0,100},""",
    """THREAT,([^,]{0,2000},){12}({src_network_zone}[^,]{1,2000}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){13}({dest_network_zone}[^,]{1,2000}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){20}({src_port}\d{1,20}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){21}({dest_port}\d{1,20}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){22}({src_translated_port}\d{1,20}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){23}({dest_translated_port}\d{1,20}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){25}({protocol}[^,]{1,2000}?)\s{0,100},""",
    """THREAT,([^,]{0,2000},){26}({action}[^,]{1,2000}?)\s{0,100},""",
    """THREAT,url,([^,]{0,2000},){26}(\\?"{1,20})?(\w{1,20}:\/{2})?(www\.)?({web_domain}[^\/\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]""",
    """,(any|unknown|({category}[^,]{1,2000}?)),Informational,client to server,"""
    ]
}
```