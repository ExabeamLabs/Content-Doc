#### Parser Content
```Java
{
Name = cef-pan-proxy
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = ArcSight
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Palo Alto Networks|PAN-OS|""", """|url|THREAT|""" ]
  Fields = [
    """\sdvc=({host}[^\s]+)""",
    """\sdvchost=({host}[\w\-.]+)""",
    """\sact=({action}[^\s]+)""",
    """\sproto=({protocol}[^\s]+)""",
    """\srt=({time}\d+)""",
    """\Wrt=({time}\W+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\ssuser=(|(({domain}[^\\=]*?)\\+)?({user}.+?))(\s+\w+=|\s*$)""",
    """\sdst=({dest_ip}.+?)(\s+\w+=|\s*$)""",
    """\sdpt=({dest_port}\d+)""",
    """\scs2=({category}[^=]+)(\s+\w+=|\s*$)""",
    """\srequestContext=(|({mime}.+?))(\s+\w+=|\s*$)""",
    """\srequest="({full_url}.+?)"(\s+\w+=|\s*$)""",
    """\srequest="(\w+\\*:\/+)?[^\/"=?]+({uri_path}\/[^?\s"]*).*?"(\s+\w+=|\s*$)""",
    """\srequest="[^\?\s"=]*?({uri_query}\?.+?)"(\s+\w+=|\s*$)""",
    """\srequest="(\w+\\*:\/+)?({web_domain}[^\/:"\s]+).*?"(\s+\w+=|\s*$)"""
    """\srequest="(\w+\\*:\/+)?(?:(\d{1,3}\.){3}\d{1,3}|([^\/]+\.)?({top_domain}[^\.\s\/:"]+\.[^\.\s\/\?:"]+)).*?"(\s+\w+=|\s*$)""",
  ]
}
```