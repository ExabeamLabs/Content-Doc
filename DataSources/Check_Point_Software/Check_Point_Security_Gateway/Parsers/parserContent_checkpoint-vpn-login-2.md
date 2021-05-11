#### Parser Content
```Java
{
Name = checkpoint-vpn-login-2
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "epoch_sec"
  Conditions = [ """product=Mobile Access""" , """cvpn_category""" , """user="""]
  Fields = [
    """\Wtime=({time}\d{1,100})""",
    """\Whostname=({host}[\w\-.]+)""",
    """\Waction=({activity}[^\|]+?)\s{0,100}\|""",
    """\Wstatus=({outcome}[^\|]+?)\s{0,100}\|""",
    """\Wuser=(({user_lastname}[^,\|\(\)]+),\s{0,100}({user_firstname}[^,\|\(\)]+?)\s{0,100}\(({user}[^\|\s\)]+)\)|({=user}[^\|\s\)]+))\s{0,100}\|""",
    """\Wreason=({failure_reason}[^\|]+?)\s{0,100}\|""",
    """\Wservice=({dest_port}\d{1,100})\s{0,100}\|""",
    """\Whost_ip=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wos_name=({os}[^\|]+?)\s{0,100}\|""",
    """\Wlogin_option=({auth_type}[^\|]+?)\s{0,100}\|""",
  ]
}
```