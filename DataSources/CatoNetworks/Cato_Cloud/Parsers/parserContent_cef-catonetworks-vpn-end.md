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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wrt=({time}\w+\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}\w+\s{1,100}\d\d\d\d)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\Wshost=({user_fullname}.+?)\s{1,100}(\w+=|$)""",
    """\Wtunnel_device_type=({os}.+?)\s{1,100}(\w+=|$)""",
  ]
}
```