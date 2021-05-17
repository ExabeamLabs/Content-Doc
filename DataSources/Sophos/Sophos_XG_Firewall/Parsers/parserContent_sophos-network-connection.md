#### Parser Content
```Java
{
Name = sophos-network-connection
  Vendor = Sophos
  Product = Sophos XG Firewall
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd' time='HH:mm:ss"
  Conditions = [ """device="SFW"""", """log_component="SSL VPN"""]
  Fields = [
    """\Wdevice_name="({host}[^"]{1,2000})""",
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """\Wstatus="({outcome}[^"]{1,2000})""",
    """\Wpriority=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc_ip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst_ip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wprotocol="({protocol}[^"]{1,2000})""",
    """\Wsrc_port=({src_port}\d{1,100})""",
    """\Wdst_port=({dest_port}\d{1,100})""",
    """\Wlog_component="({activity}[^"]{1,2000})"""",
    """\Wuser_name="({user}[^\s@"]{1,2000})"""",
    """\Wuser_name="({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})"""",
    """\Wfw_rule_id=({rule}\d{1,100})""",
    """\Win_interface=(({src_interface}\d{1,100})|"({=src_interface}[^"]{1,2000}?)")""",
    """\Wout_interface=(({dest_interface}\d{1,100})|"({=dest_interface}[^"]{1,2000}?)")""",
    """\Wreason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```