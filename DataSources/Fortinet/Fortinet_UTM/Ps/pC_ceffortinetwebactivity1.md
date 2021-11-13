#### Parser Content
```Java
{
Name = cef-fortinet-web-activity-1
  Vendor = Fortinet
  Product = Fortinet UTM
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd' time\\='HH:mm:ss"
  Conditions = [ """CEF:0|Fortinet|Fortigate|""", """|utm: webfilter|""", """url\="""]
  Fields = [
    """\Wdate\\=({time}\d\d\d\d-\d\d-\d\d time\\=\d\d:\d\d:\d\d([+-]\d\d:\d\d)?)""",
    """\Wdevname\\="{0,20}({host}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Waction\\="{0,20}({action}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wstatus\\="{0,20}({action}[^"]{1,2000})"""",
    """\Wurl\\="{0,20}(?:-|\w+:\/+[^\/]{1,2000})?({uri_path}\/[^?\s"]{0,2000})""",
    """\Wurl\\="{0,20}(?:[^?]{1,2000}?(|({uri_query}\?[^\s"]{1,2000})))["\s]{0,2000}(\w+\\=|$)""",
    """\Wcatdesc\\="{0,20}({category}[^"]{1,2000}?)["\s]{0,2000}(\w+\\=|$|,)""",
    """\Wuser\\="{0,20}({user}[^"\s]{1,2000})""",
    """\Wsrcip\\=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip\\=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Whostname\\="{0,20}({web_domain}[^"\s]{1,2000})""",
    """\Wservice\\="{0,20}({protocol}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wlevel\\="{0,20}({risk_level}[^\s"]{1,2000})"{0,20}(\s|")""",
    """\Wdstport\\=({dest_port}\d{1,100})(\s|")""",
    """\Wsentbyte\\=({bytes_out}\d{1,100})(\s|")""",
    """\Wrcvdbyte\\=({bytes_in}\d{1,100})(\s|")""",
    """\Wdevid\\="{0,20}({host_id}[^"\s]{1,2000})"{0,20}(\s|")""",
    """\Wreferralurl\\="{0,20}({referrer}[^"\s]{1,2000})""",
    """\Wgroup\\="{0,20}({user_group}.+?)["\s]{0,2000}(\w+\\=|$)""",
    """\Wmsg\\="{0,20}({additional_info}.+?)["\s]{0,2000}(\w+\\=|$)""",
    """\Waction\\="{0,20}blocked"{0,20}.+?\Wmsg\\="{0,20}({reason}.+?)["\s]{0,2000}(\w+\\=|$)""",
    """\Wmsg\\="{0,20}({reason}.+?)["\s]{0,2000}(\w+\\=|$).+?\Waction\\="{0,20}blocked"{0,20}""",
  ]


}
```