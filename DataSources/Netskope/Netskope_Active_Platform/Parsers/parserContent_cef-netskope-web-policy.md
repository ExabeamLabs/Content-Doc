#### Parser Content
```Java
{
Name = cef-netskope-web-policy
  Vendor = Netskope
  Product = Netskope Active Platform 
  DataType = "web-activity"
  Lms = Direct
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"policy"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"action":"block"""", """"traffic_type":"Web"""" ]
  Fields = [
    """"timestamp":({time}\d+)""",
    """"hostname":"({host}[^"]+)""",
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """"userip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"appcategory":"({category}[^"]+)""",
    """"action":"({action}[^"]+)""",
    """"page":"({full_url}(\w+:\/\/)?(({dest_ip}[A-Fa-f.:\d]+)|({web_domain}[^\/]+?))({uri_path}\/[^\?]*?)?({uri_query}\?[^"]+)?)"""",
    """"policy":"({additional_info}[^"]+)""",
    """"page":"({web_domain}[^\\\/"]+)""",
    """"app":"({process_name}[^"]+)"""",
    """"user":"(({user_email}[^"@]+?@[^"]+)|({user}[^"]+))"""",
    """"dstip":"({dest_ip}[A-Fa-f.:\d]+)""",
    """"browser":"(unknown|({browser}[^"]+))""",
    """"src_location":"({src_location}[^"]+)""",
    """"src_country":"({src_country}[^"]+)""",
    """"os":"({os}[^"]+)""",
    """"page":"(\w+\\*:\/+)?([^\/]*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+(?:\s\w+=|\/))[^\s:\/]+)""",
    """"referer":"({referrer}[^"]+)"""
  ]
}
```