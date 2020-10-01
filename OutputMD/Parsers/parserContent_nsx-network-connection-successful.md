#### Parser Content
```Java
{
Name = nsx-network-connection-successful
  Vendor = VMware
  Product = VMware NSX
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ INET""", """ match PASS """  ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) ({host}[\w\.\-]+)""",
    """\sINET\d* ({activity}match) ({outcome}PASS)""",
    """({direction}IN|OUT)\s+(\S+\s+)?({protocol}\w+) (\S+\s+)?({src_ip}[a-fA-F\d.:]+)(\/({src_port}\d+))?->({dest_ip}[a-fA-F\d.:]+)(\/({dest_port}\d+))?""",
  ]
}
```