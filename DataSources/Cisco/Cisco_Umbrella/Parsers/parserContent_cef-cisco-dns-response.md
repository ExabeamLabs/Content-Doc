#### Parser Content
```Java
{
Name = cef-cisco-dns-response
  Vendor = Cisco
  Product = Cisco Umbrella
  Lms = ArcSight
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""requestClientApplication=Cisco_Umbrella""", """ext_action=""","""ext_queryType="""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"responseCode":"({dns_response_code}[^"]+)"""",
    """"action":"({outcome}[^"]+)"""",
    """"queryType":"({query_type}[^"]+)"""",
    """"domain":"({query}[^"]+)"""",
    """"domain":"({query}[^"]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
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