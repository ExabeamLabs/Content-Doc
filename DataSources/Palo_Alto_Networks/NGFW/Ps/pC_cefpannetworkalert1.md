#### Parser Content
```Java
{
Name = cef-pan-network-alert-1
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zzz"
  Conditions = [ """CEF:""", """|Palo Alto Networks|PAN-OS|""", """|THREAT|""", """PanOSThreatCategory="""  ]
  Fields = [
    """\s({host}[\w\-.]{1,2000}?)\sCEF:""",
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """\|rt=({time}\w\w\w\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d \w\w\w)""",
    """({alert_type}THREAT)""",
    """\scat=({alert_name}[^=]{1,2000})\s{1,100}\w+=""",
    """\|({alert_name}[^\|]{1,2000})\|THREAT\|({alert_severity}\d{1,10})\|""",
    """\ssrc=({src_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}\w+=""",
    """\sdst=({dest_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}\w+=""",
    """\sapp=({app}[^=]{1,2000})\s{1,100}\w+=""",
    """\sproto=({protocol}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sact=({action}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sspt=({src_port}\d+)""",
    """\sdpt=({dest_port}\d+)""",
    """\scs1="{0,20}({rule}[^="]{1,2000}?)"{0,20}\s{1,20}\w+=""",
    """PanOSThreatCategory=({threat_category}[^=]{1,2000}?)\s{1,100}\w+=""",
    """suser=(({domain}[^\\=]{1,2000}?)\\{1,20})?({user}[^\s=]{1,2000})\s{1,100}\w+=""",
    """\scs2=({category}[^=]{1,2000})\s{1,100}\w+=""",
    """\sflexString2=({direction}[^=]{1,2000})\s{1,100}\w+="""
  ]


}
```