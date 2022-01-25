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
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """\sact=({action}[^\s]{1,2000})""",
    """\sproto=({protocol}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """\ssuser=(|(({domain}[^\\=]{0,2000}?)\\+)?({user}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdst=({dest_ip}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\scs2=({category}[^=]{1,2000})(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequestContext=(|({mime}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="({full_url}.+?)"(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="(\w+\\*:\/+)?[^\/"=?]{1,2000}({uri_path}\/[^?\s"]{0,2000}).*?"(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="[^\?\s"=]{0,2000}?({uri_query}\?.+?)"(\s{1,100}\w+=|\s{0,100}$)""",
    """\srequest="(\w+\\*:\/+)?({web_domain}[^\/:"\s]{1,2000}).*?"(\s{1,100}\w+=|\s{0,100}$)"""
  ]


}
```