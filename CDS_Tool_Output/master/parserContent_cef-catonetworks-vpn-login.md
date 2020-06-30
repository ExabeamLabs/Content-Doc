#### Parser Content
```Java
{
Name = cef-catonetworks-vpn-login
  Vendor = CatoNetworks
  Product = CatoNetworks
  Lms = ArcSight
  DataType = "vpn-login"
  TimeFormat = "EEE MMM dd HH:mm:ss Z yyyy"
  Conditions = [ """CEF:""", """|CatoNetworks|""", """internalType=CONNECTION""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wrt=({time}\w+\s+\w+\s+\d+\s+\d\d:\d\d:\d\d\s+\w+\s+\d\d\d\d)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wact=({outcome}.+?)\s+(\w+=|$)""",
    """\Wshost=({user_fullname}.+?)\s+(\w+=|$)""",
    """\Wtunnel_device_type=({os}.+?)\s+(\w+=|$)""",
    """\Wcs3=({account}.*?)\s\w+=.*?cs3Label=CATOAccountName""",
  ]
}
```