#### Parser Content
```Java
{
Name = cef-cisco-dns-response
  Vendor = Cisco
  Product = OpenDNS Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""requestClientApplication=Cisco_Umbrella""", """ext_action=""","""ext_queryType="""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"responseCode":"({dns_response_code}[^"]+)"""",
    """"action":"({outcome}[^"]+)"""",
    """"queryType":"({query_type}[^"]+)"""",
    """"domain":"({query}[^"]+)"""",
    """"categories":\[(""|({categories}[^]]+))""",
    """"categories":\["({category}[^"]+)""""
    """"timestamp":"({time}[^"]+)"""",
    """"internalIp":"({dest_ip}[a-fA-F:\d.]+)""",
    """"externalIp":"({src_ip}[a-fA-F:\d.]+)""",
    """"identities":\[({identities}[^\[\]]+)\]""",
    """\Wsuid=({user}[^\s]+)""",
    """\Wsuser=({user}[^\s]+)"""
  ]
}
```