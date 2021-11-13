#### Parser Content
```Java
{
Name = cef-juniper-vpn-start
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "VPN Tunneling: Session started for user" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssproc=({realm}.+?)\s{1,100}\w+=""",
    """\sspriv=({resource}.+?)\s{1,100}\w+=""",
    """\shostname\s{1,100}({src_host}[^\s|]{1,2000})""",
    """Session started for user with IP(v4)? address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""", 
  ]
  DupFields = ["user->account"]


}
```