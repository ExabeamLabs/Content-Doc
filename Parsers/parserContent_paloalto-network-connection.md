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
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,[^,]+,[^,]+,({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z),({src_ip}[^,]*?),({dest_ip}[^,]*?),({src_translated_ip}[^,]+),({dest_translated_ip}[^,]+)""",
    """THREAT,url,([^,]*,){26}("+)?.+?({web_domain}[a-z0-9\-]+\.[a-z0-9\-]{2,})[\\\/\s:"]"""
    """THREAT,([^,]*,){7}({rule}.+?)\s*,""",
    """THREAT,([^,]*,){8}(({user_email}[^@]+@[^\.]+\.[^,]+)|({user}[^,]+))"""
    """THREAT,([^,]*,){10}(not-applicable|({network_app}.+?))\s*,""",
    """THREAT,([^,]*,){12}({src_network_zone}.+?)\s*,""",
    """THREAT,([^,]*,){13}({dest_network_zone}.+?)\s*,""",
    """THREAT,([^,]*,){20}({src_port}.+?)\s*,""",
    """THREAT,([^,]*,){21}({dest_port}.+?)\s*,""",
    """THREAT,([^,]*,){22}({src_translated_port}.+?)\s*,""",
    """THREAT,([^,]*,){23}({dest_translated_port}.+?)\s*,""",
    """THREAT,([^,]*,){25}({protocol}.+?)\s*,""",
    """THREAT,([^,]*,){26}({action}.+?)\s*,""",
    """THREAT,url,([^,]*,){26}("+)?.*?({web_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ai|ms|mx|))+)[\\\/\s:"]"""
    """,(any|({category}[^,]+?)),Informational,client to server,"""
    ]
}
```