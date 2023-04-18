#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4
  Conditions = [""""queryType":"""", """"responseCode":"""", """"mostGranularIdentityType":""", """destinationServiceName =Cisco Umbrella"""]

cef-cisco-dns-response-sk4-src-template {
  Vendor = Cisco
  Product = Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}\S+)""",
    """"timestamp":"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"identities":\[[^\]]{0,2000}?"({host}[\w\-\.]{1,2000})"""",
    """"identities":\["({user_fullname}[^\("]{1,2000}?)(?:\s{0,100}\(\w{1,100}\)\s{0,100})?(\s{1,100}\(({user_email}[^@"]{1,2000}@[^@"]{1,2000})\))",("({host}[\w\-\.]{1,2000})")?""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"queryType":"[^"]{0,2000}\(({query_type}[^"\)]{1,2000})\)"""",
    """"responseCode":"({dns_response_code}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{0,2000}?)\.?"""",
    """"categories":\s{0,100}\[({categories}"{0,20}({category}[^"\],]{1,2000})[^\]]{0,2000})\]""",
    """"externalIp"{1,20}:"{1,20}({src_ip}[^"]{1,2000})"""
  
}
```