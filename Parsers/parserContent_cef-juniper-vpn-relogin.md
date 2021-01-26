#### Parser Content
```Java
{
Name = cef-juniper-vpn-relogin
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|Juniper|Pulse Secure Access|"," logged out from ", " because user started new session " ]
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