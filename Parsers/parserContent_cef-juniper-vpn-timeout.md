#### Parser Content
```Java
{
Name = cef-juniper-vpn-timeout
  Vendor = Juniper Networks
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|Juniper|Pulse Secure Access|", "|Admin Idle Timeout|" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({dest_host}.+?)(\s+\w+=|$)""",
    """\ssuser=({user}.+?)(\s+\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}.+?)(\s+\w+=|$)""",
  ]
  DupFields = [ "dest_ip->host", "dest_host->host" ]
}
```