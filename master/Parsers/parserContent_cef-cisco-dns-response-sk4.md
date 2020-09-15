#### Parser Content
```Java
{
Name = cef-cisco-dns-response-sk4
  Vendor = Cisco
  Product = OpenDNS Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:""", """|Skyformation""", """requestClientApplication=""", """Umbrella""", """cs6Label=raw-event""", """"queryType":"""", """"responseCode":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+Skyformation """,
    """"timestamp":"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"mostGranularIdentity":"({user}[^",\(\)\\\s]+)"""",
    """"mostGranularIdentity":"({user_lastname}[^",]+),\s*({user_firstname}[^",]+?)\s*(\(({domain}[^\(\)]+)\))?\s*\((({user_email}[^@"]+@[^@"]+)|({user}[^\(\)]+))\)""",
    """"mostGranularIdentity":"({user_fullname}\w+(\s+\w+)+)(\s+\((({user_email}[^@"]+@[^@"]+)|({user}\S+))\))?""",
    """identities":\[({identities}.+?)\]""",
    """"internalIp":"(|({src_ip}[a-fA-F:\d.]+))"""",
    """"action":"({outcome}[^"]+)"""",
    """"queryType":"[^"]*\(({query_type}[^"\)]+)\)"""",
    """"responseCode":"({dns_response_code}[^"]+)"""",
    """"domain":"(|({query}[^"]*?))\.?"""",
    """"categories":\[({categories}"*({category}[^"\],]+)[^\]]*)\]""",
    """\Wsuser=(anonymous|({user}[^\s@]+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(anonymous|({user_email}[^\s@]+@[^\s@]+))(\s+\w+=|\s*$)""",
    """"identities"+:\["+({dest_host}[^\.]+)[^"]+"+,"+({user_fullname}.+?)\s*\(({user_email}({user}[^@]+)@[^"\)]+)""",
    """"externalIp"+:"+({dest_ip}[^"]+)"""
  ]
}
```