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
    """\Wdevice_name="({host}[^"]+)""",
    """\Wdate=({time}\d\d\d\d-\d\d-\d\d time=\d\d:\d\d:\d\d)""",
    """\Wstatus="({outcome}[^"]+)""",
    """\Wpriority=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc_ip=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdst_ip=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wprotocol="({protocol}[^"]+)""",
    """\Wsrc_port=({src_port}\d{1,100})""",
    """\Wdst_port=({dest_port}\d{1,100})""",
    """\Wlog_component="({activity}[^"]+)"""",
    """\Wuser_name="({user}[^\s@"]+)"""",
    """\Wuser_name="({user_email}[^\s@"]+@[^\s@"]+)"""",
    """\Wfw_rule_id=({rule}\d{1,100})""",
    """\Win_interface=(({src_interface}\d{1,100})|"({=src_interface}[^"]+?)")""",
    """\Wout_interface=(({dest_interface}\d{1,100})|"({=dest_interface}[^"]+?)")""",
    """\Wreason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```