#### Parser Content
```Java
{
Name = s-f5-dns-response
  Vendor = F5 Networks
  Product = BIG-IP DNS
  Lms = Splunk
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """ q=""", """ rcode=""", """IN""", """ anslen=""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\dZ)""",
    """\ssrc=({dest_ip}[a-fA-f\d.:]+)""",
    """\sq=({query}.+?)\s+(\w+=|$)""",
    """\sq=([^.\s]+\.)*({top_query}[^.\s]+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)""",
    """\st=({query_type}\w+)""",
    """\srcode=({dns_response_code}\w+)""",
    """\sans="[^";]*?IN\s+\S+\s+({response}[^"\s;]+)""",
    """\sans="({response_full}[^"]+)"""",
  ]
}
```