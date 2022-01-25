#### Parser Content
```Java
{
Name = checkpoint-firewall-network-connection-4
  DataType = "network-connection"
  Conditions = [ """product="VPN-1 & FireWall-1"""", """,i/f_name=""", """action=drop""" ]

checkpoint-firewall-2 = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "dMMMyyyy HH:mm:ss"
  Fields = [
    """\Wtime="\s{0,100}({time}\d{1,100}\w+\d\d\d\d \d\d:\d\d:\d\d)""",
    """\Worig=({host}[^,]{1,2000})""",
    """\Waction=({action}[^,]{1,2000})""",
    """\Wrule=({rule}[^,]{1,2000})""",
    """\Wsrc=(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]{1,2000}))""",
    """\Ws_port=({src_port}\d{1,100})""",
    """\Wdst=(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^,]{1,2000}))""",
    """\Wd_port=({dest_port}\d{1,100})""",
    """\Wproto=({protocol}[^,]{1,2000})""",
    """\Wmessage_info="({alert_name}[^"]{1,2000})""",
  ]
  DupFields = [ "alert_name->alert_type" 
}
```