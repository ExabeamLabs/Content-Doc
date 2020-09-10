#### Parser Content
```Java
{
Name = cef-connectra-vpn-login
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|authcrypt|""" ]
  Fields = [
    """\srt=({time}\d+)(\s+[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s+[\w\.:]+=|$)""",
    """\sad.User=({user}.+?)(\s+[\w\.:]+=|$)""",
    """\sad.User=[^=]+?\(({user}[^\(\)]+)\)(\s+[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s+[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sad.os__name=({os}.+?)(\s+[\w\.:]+=|$)""",
    """\sad.office__mode__ip=({src_translated_ipnum}.+?)(\s+[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host"]
}

{
  Name = cef-connectra-vpn-changeip
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|ip changed|""" ]
  Fields = [
    """\srt=({time}\d+)(\s+[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s+[\w\.:]+=|$)""",
    """\sduser=({user}.+?)(\s+[\w\.:]+=|$)""",
    """\sduser=[^=]+?\(({user}[^\(\)]+)\)(\s+[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s+[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sad.os__name=({os}.+?)(\s+[\w\.:]+=|$)""",
    """\sad.assigned__IP:=({src_translated_ipnum}.+?)(\s+[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}

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
  DupFields = [ "host->dest_host" ]
}

{
  Name = cef-connectra-vpn-logout
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|logout|""" ]
  Fields = [
    """\srt=({time}\d+)(\s+[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s+[\w\.:]+=|$)""",
    """\sduser=({user}.+?)(\s+[\w\.:]+=|$)""",
    """\sduser=[^=]+?\(({user}[^\(\)]+)\)(\s+[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s+[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s+[\w\.:]+=|$)""",
    """\sad.duration=({session_duration}.+?)(\s+[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}

{
  Name = connectra-vpn-login
  Vendor = Check Point
  Product = Check Point Security Gateway
  Lms = Direct
  DataType = "vpn-start"
  TimeFormat = "ddMMMyyyy HH:mm:ss"
  Conditions = [ """|product=Connectra|""", """|event_type=Login|""", """|status=Success|""" ]
  Fields = [
    """\|(U|u)ser=({user_firstname}[^,@\|]+),\s*({user_lastname}[^@\|]+)@({domain}[^\s\|]+)\s*\(({user}[^\)\|]+)\)\s*(\||$)""",
    """\|user_dn=({user_ou}[^\|]+)\|""",
    """\|user_group=({realm}[^\|]+)""",
    """\|time=({time}\d+\w+\d\d\d\d \d+:\d+:\d+)""",
    """\|src=(?:({src_ip}[a-fA-F\d.:]+)|({src_host}[\w.\-]+))\|""",
    """\|office_mode_ip=({host}[a-fA-F\d.:]+)""",
    """\|Hostname=({host}[^\|]+)\|"""
  ]
}
```