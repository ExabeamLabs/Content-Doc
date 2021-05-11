#### Parser Content
```Java
{
Name = cef-connectra-vpn-logout
  Vendor = Check Point Software
  Product = Check Point Security Gateway
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ """|Check Point|Connectra|""", """|logout|""" ]
  Fields = [
    """\srt=({time}\d{1,100})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sduser=({user}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\sduser=[^=]+?\(({user}[^\(\)]+)\)(\s{1,100}[\w\.:]+=|$)""",
    """\sshost=({src_host}.+?)(\s{1,100}[\w\.:]+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]+=|$)""",
    """\sad.duration=({session_duration}.+?)(\s{1,100}[\w\.:]+=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```