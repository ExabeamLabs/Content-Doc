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
    """\|\s{0,100}ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
    """({host}[\w\.-]+)\s{1,100}LEEF:""",
    """usrName=({domain}[^\\\|]+)\\({user}[^\s\|]+)""",
    """\|src=({src_ip}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|srcPort=({src_port}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|dst=({dest_ip}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|dstPort=({dest_port}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|action=({action}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|URLCategory=({category}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|SourceUser=(({domain}[^\|]+)\\)?({user}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|DestinationUser=(({domain}[^\|]+)\\)?({user}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|usrName=(({domain}[^\|]+)\\)?({user}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|proto=({protocol}[^\|]+)((\|\w+=|\s{0,100}$))""",
    """\|Miscellaneous="{0,20}({full_url}[^\s]*?)("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}({web_domain}[^\/\s"]+?)(:\d{1,100}|\/|")[^\s]*?("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}([^\/\s"]+)({uri_path}\/[^\s"\?]+)[^\s]*?("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}([^\s\?"]+)(|({uri_query}\?[^\s]+?))("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}[^\s"\/\?]*?({top_domain}[^\.]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\/[^\s]*|\s{0,100})("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|ContentType=({mime}[^\|]+)""", 
 ]
}
```