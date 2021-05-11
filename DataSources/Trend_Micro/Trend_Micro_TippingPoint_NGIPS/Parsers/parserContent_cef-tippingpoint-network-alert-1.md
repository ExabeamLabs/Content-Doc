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
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|(?:\d{1,100}:\s{0,100})?({alert_name}[^\|]+)\|({alert_severity}\d{1,100})""",
    """\Wdhost=({dest_host}\S+)\s{0,100}(\w+=|$)""",
    """\Wsrc=(0\.0\.0\.0|({src_ip}[\da-fA-F\.:]+))""",
    """\Wdst=(0\.0\.0\.0|({dest_ip}[\da-fA-F\.:]+))""",
    """\sdpt=({dest_port}\d{1,100})""",
    """\sspt=({src_port}\d{1,100})""",
    """\sproto=({protocol}[^\s]+)""",
    """\scat=({additional_info}[^=]+?)\s{0,100}\w+=""",
    """app=({app}[^=]+?)\s{0,100}\w+=""",
    """\sact=({outcome}[^=\s]+?)\s{0,100}\w+="""
  ]
}
```