#### Parser Content
```Java
{
Name = cef-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ "|Cisco|Cisco ISE|", "Passed-Authentication: Authentication succeeded" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wsuser=({user}[^\s]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wcs6=Location#All Locations#AL#({location}[^,;]+)"""
    """\Wsource-ip\\=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wad\.NetworkDeviceName=({network}[^,\s]+)"""
  ]
  DupFields = [ "dest_ip->auth_server" ]
}
```