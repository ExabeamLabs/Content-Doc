#### Parser Content
```Java
{
Name = cef-connectra-vpn-changeip
  Vendor = Check Point Software
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
```