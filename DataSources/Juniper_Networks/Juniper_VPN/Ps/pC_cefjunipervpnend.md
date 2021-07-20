#### Parser Content
```Java
{
Name = cef-juniper-vpn-end
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "VPN Tunneling: Session ended for user" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}sproc=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssproc=({realm}.+?)\s{1,100}spriv""",
    """\sspriv=({resource}.+?)\s{1,100}\w+=""",
    """\sshost=({src_host}[^\s]{1,2000})""",
    """Session ended for user with IP(v4)? address ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```