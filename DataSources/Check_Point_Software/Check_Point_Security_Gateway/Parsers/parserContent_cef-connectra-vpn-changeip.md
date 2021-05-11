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
    """\srt=({time}\d{1,100})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sduser=({user}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sduser=[^=]+?\(({user}[^\(\)]+)\)(\s{1,100}[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sad.os__name=({os}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sad.assigned__IP:=({src_translated_ipnum}.+?)(\s{1,100}[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```