#### Parser Content
```Java
{
Name = checkpoint-vpn-login-2
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """product=Mobile Access""" , """cvpn_category""" , """user="""]
  Fields = [
    """\Wtime=({time}\d+)""",
    """\Whostname=({host}[\w\-.]+)""",
    """\Waction=({activity}[^\|]+?)\s*\|""",
    """\Wstatus=({outcome}[^\|]+?)\s*\|""",
    """\Wuser=({user_lastname}[^,\|\(\)]+),\s*({user_firstname}[^,\|\(\)]+?)\s*\(({user}[^\|\s\)]+)\)\s*\|""",
    """\Wreason=({failure_reason}[^\|]+?)\s*\|""",
    """\Wservice=({dest_port}\d+)\s*\|""",
    """\Whost_ip=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wos_name=({os}[^\|]+?)\s*\|""",
    """\Wlogin_option=({auth_type}[^\|]+?)\s*\|""",
  ]
}
```