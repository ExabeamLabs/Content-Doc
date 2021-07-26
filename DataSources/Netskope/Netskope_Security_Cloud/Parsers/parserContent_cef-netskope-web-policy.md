#### Parser Content
```Java
{
Name = cef-netskope-web-policy
  Vendor = Netskope
  Product = Netskope Security Cloud
  DataType = "web-activity"
  Lms = Direct
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"policy"""", """destinationServiceName=Netskope""", """|security-threat-detected|""", """"action":"block"""", """"traffic_type":"Web"""" ]
  Fields = [
    """"timestamp":({time}\d{1,100})""",
    """"hostname":"({host}[^"]{1,2000})""",
    """"srcip":"({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """"userip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"appcategory":"({category}[^"]{1,2000})""",
    """"action":"({action}[^"]{1,2000})""",
    """"page":"({full_url}(\w+:\/\/)?(({dest_ip}[A-Fa-f.:\d]{1,2000})|({web_domain}[^\/]{1,2000}?))({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?[^"]{1,2000})?)"""",
    """"policy":"({additional_info}[^"]{1,2000})""",
    """"page":"({web_domain}[^\\\/"]{1,2000})""",
    """"app":"({process_name}[^"]{1,2000})"""",
    """"user":"(({user_email}[^"@]{1,2000}?@[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"dstip":"({dest_ip}[A-Fa-f.:\d]{1,2000})""",
    """"browser":"(unknown|({browser}[^"]{1,2000}))""",
    """"src_location":"({src_location}[^"]{1,2000})""",
    """"src_country":"({src_country}[^"]{1,2000})""",
    """"os":"({os}[^"]{1,2000})""",
    """"page":"(\w+\\*:\/+)?([^\/]{0,2000}?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d{1,100})?)+(?:\s\w+=|\/))[^\s:\/]{1,2000})""",
    """"referer":"({referrer}[^"]{1,2000})"""
  ]
}
```