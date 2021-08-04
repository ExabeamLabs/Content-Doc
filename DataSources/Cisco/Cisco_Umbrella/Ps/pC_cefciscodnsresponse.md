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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"responseCode":"({dns_response_code}[^"]{1,2000})"""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"queryType":"({query_type}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{1,2000})"""",
    """"domain":"({query}[^"]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
    """"categories":\[(""|({categories}[^]]{1,2000}))""",
    """"categories":\["({category}[^"]{1,2000})""""
    """"timestamp":"({time}[^"]{1,2000})"""",
    """"internalIp":"({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"externalIp":"({src_ip}[a-fA-F:\d.]{1,2000})""",
    """"identities":\[({identities}[^\[\]]{1,2000})\]""",
    """\Wsuid=({user}[^\s]{1,2000})""",
    """\Wsuser=({user}[^\s]{1,2000})"""
  ]
}
```