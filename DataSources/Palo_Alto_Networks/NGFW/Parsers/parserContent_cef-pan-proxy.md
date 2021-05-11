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
    """\srt=({time}\d{1,100})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\ssuser=(|(({domain}[^\\=]*?)\\+)?({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=({dest_ip}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\scs2=({category}[^=]+)(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequestContext=(|({mime}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="({full_url}.+?)"(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="(\w+\\*:\/+)?[^\/"=?]+({uri_path}\/[^?\s"]*).*?"(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="[^\?\s"=]*?({uri_query}\?.+?)"(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="(\w+\\*:\/+)?({web_domain}[^\/:"\s]+).*?"(\s{1,100}\w+=|\s{0,100}$)"""
    """\srequest="(\w+\\*:\/+)?(?:(\d{1,3}\.){3}\d{1,3}|([^\/]+\.)?({top_domain}[^\.\s\/:"]+\.[^\.\s\/\?:"]+)).*?"(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```