#### Parser Content
```Java
{
Name = cef-juniper-vpn-start
  Vendor = Juniper Networks
  Lms = ArcSight
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "VPN Tunneling: Session started for user" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s+\w+=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssproc=({realm}.+?)\s+\w+=""",
    """\sspriv=({resource}.+?)\s+\w+=""",
    """\shostname\s+({src_host}[^\s|]+)""",
    """Session started for user with IP(v4)? address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```