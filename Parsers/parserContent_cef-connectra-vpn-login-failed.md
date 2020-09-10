#### Parser Content
```Java
{
Name = cef-connectra-vpn-login-failed
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|authcrypt_failed|""" ]
  Fields = [
    """\srt=({time}\d+)(\s+[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s+[\w\.:]+=|$)""",
    """\sad.User=({user}.+?)(\s+[\w\.:]+=|$)""",
    """\sad.User=[^=]+?\(({user}[^\(\)]+)\)(\s+[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s+[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\smsg=({failure_reason}.+?)(\s+[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host" , "user->account"]
}

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