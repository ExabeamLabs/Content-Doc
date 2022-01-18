#### Parser Content
```Java
{
Name = s-f5-dns-response
  Vendor = F5
  Product = BIG-IP DNS
  Lms = Splunk
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """ q=""", """ rcode=""", """IN""", """ anslen=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\dZ)""",
    """\ssrc=({dest_ip}[a-fA-f\d.:]{1,2000})""",
    """\sq=({query}.+?)\s{1,100}(\w+=|$)""",
    """\sq=([^.\s]{1,2000}\.)*({top_query}[^.\s]{1,2000}\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)""",
    """\st=({query_type}\w+)""",
    """\srcode=({dns_response_code}\w+)""",
    """\sans="[^";]{0,2000}?IN\s{1,100}\S+\s{1,100}({response}[^"\s;]{1,2000})""",
    """\sans="({response_full}[^"]{1,2000})"""",
  ]


}
```