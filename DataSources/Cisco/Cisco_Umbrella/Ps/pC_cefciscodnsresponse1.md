#### Parser Content
```Java
{
Name = cef-cisco-dns-response-1
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""CEF:0|Skyformation""", """requestClientApplication=Umbrella""", """cs6Label=raw-event"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """cs6="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)","[^"]{0,2000}","({user_lastname}[^",]{1,2000}),\s{0,100}({user_firstname}[^",\s]{1,2000})\s{0,100}\(({domain}[^\(\)]{1,2000})\)\s{0,100}\(({user}[^\(\)]{1,2000})\)[^"]{0,2000}?","(|({dest_ip}[a-fA-F:\d.]{1,2000}))",("[^"]{1,2000}",)"(|({outcome}[^"]{1,2000}))","[^"]{1,2000}\(({query_type}[^\)]{1,2000})\)(",")(|({dns_response_code}[^"]{1,2000}))(",")(|({query}[^"]{1,2000}))(",")(|({category}[^"]{1,2000}))"""",
    """cs6="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)","[^"]{0,2000}","({user_lastname}[^",]{1,2000}),\s{0,100}({user_firstname}[^",\s]{1,2000})\s{0,100}\(({domain}[^\(\)]{1,2000})\)\s{0,100}\(({user}[^\(\)]{1,2000})\)[^"]{0,2000}?","(|({dest_ip}[a-fA-F:\d.]{1,2000}))",("[^"]{1,2000}",)"(|({outcome}[^"]{1,2000}))","[^"]{1,2000}\(({query_type}[^\)]{1,2000})\)(",")(|({dns_response_code}[^"]{1,2000}))(",")(|({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))))(",")(|({category}[^"]{1,2000}))"""",
  ]


}
```