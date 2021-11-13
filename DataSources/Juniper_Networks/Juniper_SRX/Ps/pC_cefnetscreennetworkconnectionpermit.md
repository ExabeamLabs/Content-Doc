#### Parser Content
```Java
{
Name = cef-netscreen-network-connection-permit
  Conditions = [ """CEF:""", """|NetScreen Traffic Permit|""" ]

cef-netscreen-network-connection = {
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wact=({activity}.+?)(\s{1,100}[\w\-]{1,2000}=|\s{0,100}$)""",
    """\Wproto=({protocol}.+?)(\s{1,100}[\w\-]{1,2000}=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wshost=({src_host}.+?)(\s{1,100}[\w\-]{1,2000}=|\s{0,100}$)""",
    """\Wsuser=({user}.+?)(\s{1,100}[\w\-]{1,2000}=|\s{0,100}$)""",
    """\Wcat=({rule}.+?)(\s{1,100}[\w\-]{1,2000}=|\s{0,100}$)""",
    """\WnitroReason=({reason}.+?)(\s{1,100}[\w\-]{1,2000}=|\s{0,100}$)""",
  
}
```