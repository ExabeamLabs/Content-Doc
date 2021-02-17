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
    """\Wdvchost=({host}\S+)\s*(\w+=|$)""",
    """\Wrt=({time}\d+)""",
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|(?:\d+:\s*)?({alert_name}[^\|]+)\|({alert_severity}\d+)""",
    """\Wdhost=({dest_host}\S+)\s*(\w+=|$)""",
    """\Wsrc=(0\.0\.0\.0|({src_ip}[\da-fA-F\.:]+))""",
    """\Wdst=(0\.0\.0\.0|({dest_ip}[\da-fA-F\.:]+))""",
    """\sdpt=({dest_port}\d+)""",
    """\sspt=({src_port}\d+)""",
    """\sproto=({protocol}[^\s]+)""",
    """\scat=({additional_info}[^=]+?)\s*\w+=""",
    """app=({app}[^=]+?)\s*\w+=""",
    """\sact=({outcome}[^=\s]+?)\s*\w+="""
  ]
}
```