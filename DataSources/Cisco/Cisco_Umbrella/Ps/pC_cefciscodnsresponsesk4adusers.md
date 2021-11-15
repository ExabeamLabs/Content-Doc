#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4-ad-users
  Conditions = ["""CEF:""", """|Skyformation""", """destinationServiceName =Cisco Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""", """"mostGranularIdentityType":"AD Users""""]
  Fields=${CiscoParsersTemplates.cef-cisco-dns-response-sk4-src-template.Fields}[
    """"mostGranularIdentity":"({user_fullname}[^\("]{1,2000}?)(?:\s{0,100}\(\w+\)\s{0,100})?(\s{1,100}\((({user_email}[^@"]{1,2000}@[^@"]{1,2000})|({user}[^"]{1,2000}))\))"""",
  ]

cef-cisco-dns-response-sk4-src-template {
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}\S+)""",
    """"timestamp":"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"identities":\["(({user}\w{1,2000})|({host}[\w\-\.]{1,2000}))"""",
    """"identities":\["({user_fullname}[^\("]{1,2000}?)(?:\s{0,100}\(\w{1,100}\)\s{0,100})?(\s{1,100}\(({user_email}[^@"]{1,2000}@[^@"]{1,2000})\))",("({host}[\w\-\.]{1,2000})")?""",
    """"internalIp":"({src_ip}[a-fA-F:\d.]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"queryType":"[^"]{0,2000}\(({query_type}[^"\)]{1,2000})\)"""",
    """"responseCode":"({dns_response_code}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{0,2000}?)\.?"""",
    """"categories":\s{0,100}\[({categories}"{0,20}({category}[^"\],]{1,2000})[^\]]{0,2000})\]""",
    """"externalIp"{1,20}:"{1,20}({dest_ip}[^"]{1,2000})"""
  
}
```