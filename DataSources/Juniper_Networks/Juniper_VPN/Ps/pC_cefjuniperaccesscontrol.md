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
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}sproc=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sspriv=({resource}.+?)\s{1,100}\w+=""",
    """\sahost=({dest_host}.*?)\s{1,100}\w+=""",
    """\sagt=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\scs6=({realm}.*?)\s{1,100}\w+=.*?cs6Label=Group Name""",
  ]
  DupFields = ["user->account"]


}
```