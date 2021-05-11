#### Parser Content
```Java
{
Name = windows-dns-response
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """UDP response info at """, """Buf length =""" ]
  Fields = [
    """exabeam_host=({host}[^\s]*)""",
    """({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (AM|am|PM|pm))""",
    """({protocol}UDP)\s{1,100}({activity}Snd)\s{1,100}({dest_ip}[a-fA-F\d.:]+)""",
    """Remote addr\s{0,100}({dest_ip}[a-fA-F\d.:]+),\s{0,100}port\s{0,100}({dest_port}\d{1,100})""",
    """XID\s{1,100}0x({query_id}[\da-fA-F]+)""",
    """QTYPE\s{1,100}({query_type}\w+)""",
    """RCODE\s{1,100}[^(]*?\(({dns_response_code}[^(]+)\)""",
    """QUESTION SECTION:.*?Name\s{1,100}"({query}[^"]+)"""",
    """QUESTION SECTION:.*?Name\s{1,100}"[^"]*({top_query}(\(\d{1,100}\)[^\(\)"]+)\(0\))"""",
    """QUESTION SECTION:.*?Name\s{1,100}"[^"]*({top_query}(\(\d{1,100}\)[^\(\)"]+){2}\(0\))"""",
    """QUESTION SECTION:.*?Name\s{1,100}"(\(\d{1,100}\)[^\)\)]+)*({top_query}\(\d{1,100}\)[^\(\)\/\s]+(?i)(\(\d{1,100}\)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+\(0\))"""",
    """Buf length\s{0,100}=\s{0,100}\S+\s{0,100}\(({bytes}\d{1,100})""",
    """ANSWER SECTION:(\s{0,100}empty|.+?DATA\s{1,100}({response}\S+))"""
  ]
}
```