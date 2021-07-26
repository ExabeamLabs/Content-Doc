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
    """\srt=({time}\d{1,100})(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sdvchost=({host}.+?)(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sduser=({user}.+?)(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sduser=[^=]{1,2000}?\(({user}[^\(\)]{1,2000})\)(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sshost=({src_host}.+?)(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sad.os__name=({os}.+?)(\s{1,100}[\w\.:]{1,2000}=|$)""",
    """\sad.assigned__IP:=({src_translated_ipnum}.+?)(\s{1,100}[\w\.:]{1,2000}=|$)""",
  ]
  DupFields = [ "host->dest_host" ]
}
```