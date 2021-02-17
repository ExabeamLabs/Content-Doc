#### Parser Content
```Java
{
Name = cef-catonetworks-vpn-end
  Vendor = CatoNetworks
  Product = Cato Cloud
  Lms = ArcSight
  DataType = "vpn-end"
  TimeFormat = "EEE MMM dd HH:mm:ss Z yyyy"
  Conditions = [ """CEF:""", """|CatoNetworks|""", """internalType=DISCONNECTED""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wrt=({time}\w+\s+\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\w+\s+\d\d\d\d)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
    """\Wshost=({user_fullname}.+?)\s+(\w+=|$)""",
    """\Wtunnel_device_type=({os}.+?)\s+(\w+=|$)""",
  ]
}
```