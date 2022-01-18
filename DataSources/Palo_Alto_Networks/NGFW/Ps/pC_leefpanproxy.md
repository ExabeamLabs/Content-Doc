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
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """({host}[\w\.-]{1,2000})\s{1,100}LEEF:""",
    """usrName =({domain}[^\\\|]{1,2000})\\({user}[^\s\|]{1,2000})""",
    """\|src=({src_ip}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|srcPort=({src_port}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|dst=({dest_ip}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|dstPort=({dest_port}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|action=({action}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|URLCategory=({category}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|SourceUser=(({domain}[^\|]{1,2000})\\)?({user}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|DestinationUser=(({domain}[^\|]{1,2000})\\)?({user}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|usrName =(({domain}[^\|]{1,2000})\\)?({user}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|proto=({protocol}[^\|]{1,2000})((\|\w+=|\s{0,100}$))""",
    """\|Miscellaneous="{0,20}({full_url}[^\s]{0,2000}?)("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}({web_domain}[^\/\s"]{1,2000}?)(:\d{1,100}|\/|")[^\s]{0,2000}?("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}([^\/\s"]{1,2000})({uri_path}\/[^\s"\?]{1,2000})[^\s]{0,2000}?("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}([^\s\?"]{1,2000})(|({uri_query}\?[^\s]{1,2000}?))("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|Miscellaneous="{0,20}[^\s"\/\?]{0,2000}?({top_domain}[^\.]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\/[^\s]{0,2000}|\s{0,100})("{1,20}\|\w+=|"{1,20}\s{0,100}$|\s{0,100}$)""",
    """\|ContentType=({mime}[^\|]{1,2000})""", 
 ]


}
```