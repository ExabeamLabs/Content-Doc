#### Parser Content
```Java
{
Name = cef-sophos-network-connection
  Vendor = Sophos
  Product = Sophos XG Firewall
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Sophos|SFW|""", """Firewall""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wlog_component="({activity}[^"]+)"""",
    """\WcategoryOutcome=({outcome}[^"\s]+)""",
    """\Wstatus="({outcome}[^"]+)"""",
    """\Wsuser=({user}[^\s@"]+)@({domain}[^\s@"]+)"""",
    """\Wuser_name="({user}[^\s@"]+)"""",
    """\Wuser_name="({user_email}[^\s@"]+@[^\s@"]+)"""",
    """\Wsrc(_ip)?=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wfw_rule_id=({rule}\d+)""",
    """\Win_interface=({src_interface}\d+)""",
    """\Wout_interface=({dest_interface}\d+)""",
    """\Wreason=({failure_reason}.+?)\s+(\w+=|$)""",
  ]
}
```