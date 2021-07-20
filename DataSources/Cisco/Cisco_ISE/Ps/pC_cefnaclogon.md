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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wsuser=(({user_type}host)\/)?({user}[^\s]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wcs6=Location#All Locations#AL#({location}[^,;]{1,2000})"""
    """\Wsource-ip\\=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wad\.NetworkDeviceName=({network}[^,\s]{1,2000})"""
  ]
  DupFields = [ "dest_ip->auth_server" , "dest_host->computer_name"]
}
```