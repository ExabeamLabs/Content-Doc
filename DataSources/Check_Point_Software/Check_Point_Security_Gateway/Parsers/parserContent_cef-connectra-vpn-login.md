#### Parser Content
```Java
{
Name = cef-connectra-vpn-login
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|authcrypt|""" ]
  Fields = [
    """\srt=({time}\d{1,100})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sad.User=({user}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sad.User=[^=]+?\(({user}[^\(\)]+)\)(\s{1,100}[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sad.os__name=({os}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sad.office__mode__ip=({src_translated_ipnum}.+?)(\s{1,100}[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host", "user->account"]
}
```