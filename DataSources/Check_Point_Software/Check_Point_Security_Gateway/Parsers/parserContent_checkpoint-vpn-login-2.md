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
    """\Whostname=({host}[\w\-.]{1,2000})""",
    """\Waction=({activity}[^\|]{1,2000}?)\s{0,100}\|""",
    """\Wstatus=({outcome}[^\|]{1,2000}?)\s{0,100}\|""",
    """\Wuser=(({user_lastname}[^,\|\(\)]{1,2000}),\s{0,100}({user_firstname}[^,\|\(\)]{1,2000}?)\s{0,100}\(({user}[^\|\s\)]{1,2000})\)|({=user}[^\|\s\)]{1,2000}))\s{0,100}\|""",
    """\Wreason=({failure_reason}[^\|]{1,2000}?)\s{0,100}\|""",
    """\Wservice=({dest_port}\d{1,100})\s{0,100}\|""",
    """\Whost_ip=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wos_name=({os}[^\|]{1,2000}?)\s{0,100}\|""",
    """\Wlogin_option=({auth_type}[^\|]{1,2000}?)\s{0,100}\|""",
  ]
}
```