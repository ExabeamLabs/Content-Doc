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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wlog_component="({activity}[^"]{1,2000})"""",
    """\WcategoryOutcome=({outcome}[^"\s]{1,2000})""",
    """\Wstatus="({outcome}[^"]{1,2000})"""",
    """\Wsuser=({user}[^\s@"]{1,2000})@({domain}[^\s@"]{1,2000})"""",
    """\Wuser_name="({user}[^\s@"]{1,2000})"""",
    """\Wuser_name="({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})"""",
    """\Wsrc(_ip)?=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wfw_rule_id=({rule}\d{1,100})""",
    """\Win_interface=({src_interface}\d{1,100})""",
    """\Wout_interface=({dest_interface}\d{1,100})""",
    """\Wreason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```