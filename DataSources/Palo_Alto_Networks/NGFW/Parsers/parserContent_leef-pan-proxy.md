#### Parser Content
```Java
{
Name = leef-pan-proxy
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = QRadar
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """LEEF:""", """|Palo Alto Networks|PAN-OS Syslog Integration|""", """|cat=THREAT|""", """ubtype=url|""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|\s*ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s+LEEF:""",
    """usrName=({domain}[^\\\|]+)\\({user}[^\s\|]+)""",
    """\|src=({src_ip}[^\|]+)((\|\w+=|\s*$))""",
    """\|srcPort=({src_port}[^\|]+)((\|\w+=|\s*$))""",
    """\|dst=({dest_ip}[^\|]+)((\|\w+=|\s*$))""",
    """\|dstPort=({dest_port}[^\|]+)((\|\w+=|\s*$))""",
    """\|action=({action}[^\|]+)((\|\w+=|\s*$))""",
    """\|URLCategory=({category}[^\|]+)((\|\w+=|\s*$))""",
    """\|SourceUser=(({domain}[^\|]+)\\)?({user}[^\|]+)((\|\w+=|\s*$))""",
    """\|DestinationUser=(({domain}[^\|]+)\\)?({user}[^\|]+)((\|\w+=|\s*$))""",
    """\|usrName=(({domain}[^\|]+)\\)?({user}[^\|]+)((\|\w+=|\s*$))""",
    """\|proto=({protocol}[^\|]+)((\|\w+=|\s*$))""",
    """\|Miscellaneous="*({full_url}[^\s]*?)("+\|\w+=|"+\s*$|\s*$)""",
    """\|Miscellaneous="*({web_domain}[^\/\s"]+)[^\s]*?("+\|\w+=|"+\s*$|\s*$)""",
    """\|Miscellaneous="*([^\/\s"]+)\/({uri_path}[^\s"\?]+)[^\s]*?("+\|\w+=|"+\s*$|\s*$)""",
    """\|Miscellaneous="*([^\s\?"]+)\?(|({uri_query}[^\s]+?))("+\|\w+=|"+\s*$|\s*$)""",
    """\|Miscellaneous="*[^\s"\/\?]*?({top_domain}[^\.]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\/[^\s]*|\s*)("+\|\w+=|"+\s*$|\s*$)""",
    """\|ContentType=({mime}[^\|]+)""", 
 ]
}
```