#### Parser Content
```Java
{
Name = windows-dns-query
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-query"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """UDP question info at """, """Buf length =""" ]
  Fields = [
    """exabeam_host=({host}[^\s]*)""",
    """({time}\d+\/\d+\/\d\d\d\d \d+:\d+:\d+ (AM|am|PM|pm))""",
    """({protocol}UDP)\s+({activity}Rcv)\s+({src_ip}[a-fA-F\d.:]+)""",
    """Remote addr\s*({src_ip}[a-fA-F\d.:]+),\s*port\s*({src_port}\d+)""",
    """XID\s+0x({query_id}[\da-fA-F]+)""",
    """QTYPE\s+({query_type}\w+)""",
    """RCODE\s+[^(]*?\(({result}[^(]+)\)""",
    """QUESTION SECTION:.*?Name\s+"({query}[^"]+)"""",
    """QUESTION SECTION:.*?Name\s+"[^"]*({top_query}(\(\d+\)[^\(\)"]+)\(0\))"""",
    """QUESTION SECTION:.*?Name\s+"[^"]*({top_query}(\(\d+\)[^\(\)"]+){2}\(0\))"""",
    """QUESTION SECTION:.*?Name\s+"(\(\d+\)[^\)\)]+)*({top_query}\(\d+\)[^\(\)\/\s]+(?i)(\(\d+\)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+\(0\))"""",
    """Buf length\s*=\s*\S+\s*\(({bytes}\d+)""",
    """ANSWER SECTION:(\s*empty|.+?DATA\s+({response}\S+))"""
  ]
}
```