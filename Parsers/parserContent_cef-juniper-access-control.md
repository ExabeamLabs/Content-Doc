#### Parser Content
```Java
{
Name = cef-juniper-access-control
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "access-control"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|Agent login succeeded for" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s+sproc=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sspriv=({resource}.+?)\s+\w+=""",
    """\sahost=({dest_host}.*?)\s+\w+=""",
    """\sagt=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs6=({realm}.*?)\s+\w+=.*?cs6Label=Group Name""",
  ]
  DupFields = ["user->account"]
}
```