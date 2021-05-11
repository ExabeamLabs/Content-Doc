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
    """\Wdevname\\="{0,20}({host}[^\s"]+)"{0,20}(\s|")""",
    """\Waction\\="{0,20}({action}[^\s"]+)"{0,20}(\s|")""",
    """\Wstatus\\="{0,20}({action}[^"]+)"""",
    """\Wurl\\="{0,20}(?:-|\w+:\/+[^\/]+)?({uri_path}\/[^?\s"]*)""",
    """\Wurl\\="{0,20}(?:[^?]+?(|({uri_query}\?[^\s"]+)))["\s]*(\w+\\=|$)""",
    """\Wcatdesc\\="{0,20}({category}[^"]+?)["\s]*(\w+\\=|$|,)""",
    """\Wuser\\="{0,20}({user}[^"\s]+)""",
    """\Wsrcip\\=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdstip\\=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Whostname\\="{0,20}({web_domain}[^"\s]+)""",
    """\Wservice\\="{0,20}({protocol}[^\s"]+)"{0,20}(\s|")""",
    """\Wlevel\\="{0,20}({risk_level}[^\s"]+)"{0,20}(\s|")""",
    """\Wdstport\\=({dest_port}\d{1,100})(\s|")""",
    """\Wsentbyte\\=({bytes_out}\d{1,100})(\s|")""",
    """\Wrcvdbyte\\=({bytes_in}\d{1,100})(\s|")""",
    """\Wdevid\\="{0,20}({host_id}[^"\s]+)"{0,20}(\s|")""",
    """\Wreferralurl\\="{0,20}({referrer}[^"\s]+)""",
    """\Wgroup\\="{0,20}({user_group}.+?)["\s]*(\w+\\=|$)""",
    """\Wmsg\\="{0,20}({additional_info}.+?)["\s]*(\w+\\=|$)""",
    """\Waction\\="{0,20}blocked"{0,20}.+?\Wmsg\\="{0,20}({reason}.+?)["\s]*(\w+\\=|$)""",
    """\Wmsg\\="{0,20}({reason}.+?)["\s]*(\w+\\=|$).+?\Waction\\="{0,20}blocked"{0,20}""",
    """\Whostname\\="{0,20}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^"\s]*\.)?({top_domain}[^\s\/."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|by|mx))+)""",
  ]
}
```