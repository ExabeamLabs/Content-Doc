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
    """"identities":\["(({user}\w+)|({host}[\w\-\.]{1,2000}))"""",
    """"identities":\["({user_fullname}[^\("]{1,2000}?)(?:\s{0,100}\(\w+\)\s{0,100})?(\s{1,100}\(({user_email}[^@"]{1,2000}@[^@"]{1,2000})\))",("({host}[\w\-\.]{1,2000})")?""",
    """"mostGranularIdentity":"({user_fullname}[^\("]{1,2000}?)(?:\s{0,100}\(\w+\)\s{0,100})?(\s{1,100}\((({user_email}[^@"]{1,2000}@[^@"]{1,2000})|({user}[^"]{1,2000}))\))"""",
    """"internalIp":"({src_ip}[a-fA-F:\d.]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"queryType":"[^"]{0,2000}\(({query_type}[^"\)]{1,2000})\)"""",
    """"responseCode":"({dns_response_code}[^"]{1,2000})"""",
    """"domain":"(|({query}[^"]{0,2000}?\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))))\.?"""",
    """"domain":"({query}[^"]{0,2000}?)\.?"""",
    """"categories":\s{0,100}\[({categories}"{0,20}({category}[^"\],]{1,2000})[^\]]{0,2000})\]""",
    """"externalIp"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})"""
  ]
}
```