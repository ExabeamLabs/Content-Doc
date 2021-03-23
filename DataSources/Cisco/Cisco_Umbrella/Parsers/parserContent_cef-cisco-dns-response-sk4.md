#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation""", """requestClientApplication=""", """Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""" ]
  Fields = [
    """exabeam_host=({host}\S+)""",
    """"timestamp":"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"identities":\["(({user}\w+)|({host}[\w\-\.]+))"""",
    """"identities":\["({user_fullname}[^\("]+?)(?:\s*\(\w+\)\s*)?(\s+\(({user_email}[^@"]+@[^@"]+)\))",("({host}[\w\-\.]+)")?""",
    """"mostGranularIdentity":"({user_fullname}[^\("]+?)(?:\s*\(\w+\)\s*)?(\s+\((({user_email}[^@"]+@[^@"]+)|({user}[^"]+))\))"""",
    """"internalIp":"({src_ip}[a-fA-F:\d.]+)"""",
    """"action":"({outcome}[^"]+)"""",
    """"queryType":"[^"]*\(({query_type}[^"\)]+)\)"""",
    """"responseCode":"({dns_response_code}[^"]+)"""",
    """"domain":"(|({query}[^"]*?\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))))\.?"""",
    """"domain":"({query}[^"]*?)\.?"""",
    """"categories":\s*\[({categories}"*({category}[^"\],]+)[^\]]*)\]""",
    """"externalIp"+:"+({dest_ip}[^"]+)"""
  ]
}
```