#### Parser Content
```Java
{
Name = cef-palo-alto-networks-security-alert-1
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = ArcSight
  DataType = "network-alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zzz"
  Conditions = [ """CEF""", """|Palo Alto Networks|PAN-OS|""", """|THREAT|""", """cat=spyware"""  ]
  Fields = [
    """\sdvchost=({host}[\w\-.]{1,2000})""",
    """\|rt=({time}\w\w\w\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d \w\w\w)""",
    """({alert_type}spyware)""",
    """\scat=({alert_name}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """Palo Alto Networks\|PAN-OS\|[^\|]{1,2000}\|({alert_name}[^(:]{1,2000})(\s{0,100}[^\|]{1,2000})\|""",
    """Palo Alto Networks\|PAN-OS\|([^\|]{1,2000}\|){3}({alert_severity}\d)\|rt=""",
    """\sshost=({src_host}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdhost=({dest_host}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssrc=({src_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}(\w+=|$)""",
    """\sdst=({dest_ip}[A-Fa-f\d:.]{1,2000})\s{1,100}(\w+=|$)""",
    """\seventId=({alert_id}\d{1,100})\s{1,100}(\w+=|$)""",
    """\sapp=({threat_category}[^=]{1,2000})\s{1,100}(\w+=|$)""",
    """\sproto=({protocol}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sact=({action}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\sspt=({src_port}\d+)""",
    """\sdpt=({dest_port}\d+)""",
    """\scs1="{0,20}({rule}[^="]{1,2000}?)"{0,20}\s{1,20}\w+="""
  ]


}
```