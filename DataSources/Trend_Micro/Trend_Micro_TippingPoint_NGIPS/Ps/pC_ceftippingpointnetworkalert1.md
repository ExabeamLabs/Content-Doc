#### Parser Content
```Java
{
Name = cef-tippingPoint-network-alert-1
  Vendor = Trend Micro
  Product = Trend Micro TippingPoint NGIPS
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|TippingPoint|UnityOne|""", """app=""" ]
  Fields = [
    """\Wdvchost=({host}\S+)\s{0,100}(\w+=|$)""",
    """\Wrt=({time}\d{1,100})""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})\|(?:\d{1,100}:\s{0,100})?({alert_name}[^\|]{1,2000})\|({alert_severity}\d{1,100})""",
    """\Wdhost=({dest_host}\S+)\s{0,100}(\w+=|$)""",
    """\Wsrc=(0\.0\.0\.0|({src_ip}[\da-fA-F\.:]{1,2000}))""",
    """\Wdst=(0\.0\.0\.0|({dest_ip}[\da-fA-F\.:]{1,2000}))""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\sspt=({src_port}\d{1,100})""",
    """\sproto=({protocol}[^\s]{1,2000})""",
    """\scat=({additional_info}[^=]{1,2000}?)\s{0,100}\w+=""",
    """app=({app}[^=]{1,2000}?)\s{0,100}\w+=""",
    """\sact=({outcome}[^=\s]{1,2000}?)\s{0,100}\w+="""
  ]


}
```