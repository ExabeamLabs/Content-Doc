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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """cs6="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)","[^"]*","({user_lastname}[^",]+),\s{0,100}({user_firstname}[^",\s]+)\s{0,100}\(({domain}[^\(\)]+)\)\s{0,100}\(({user}[^\(\)]+)\)[^"]*?","(|({dest_ip}[a-fA-F:\d.]+))",("[^"]+",)"(|({outcome}[^"]+))","[^"]+\(({query_type}[^\)]+)\)(",")(|({dns_response_code}[^"]+))(",")(|({query}[^"]+))(",")(|({category}[^"]+))"""",
    """cs6="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)","[^"]*","({user_lastname}[^",]+),\s{0,100}({user_firstname}[^",\s]+)\s{0,100}\(({domain}[^\(\)]+)\)\s{0,100}\(({user}[^\(\)]+)\)[^"]*?","(|({dest_ip}[a-fA-F:\d.]+))",("[^"]+",)"(|({outcome}[^"]+))","[^"]+\(({query_type}[^\)]+)\)(",")(|({dns_response_code}[^"]+))(",")(|({query}[^"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))))(",")(|({category}[^"]+))"""",
  ]
}
```