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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) ({host}[\w\.\-]{1,2000})""",
    """\sINET\d{0,100} ({activity}match) ({outcome}PASS)""",
    """({direction}IN|OUT)\s{1,100}(\S+\s{1,100})?({protocol}\w+) (\S+\s{1,100})?({src_ip}[a-fA-F\d.:]{1,2000})(\/({src_port}\d{1,100}))?->({dest_ip}[a-fA-F\d.:]{1,2000})(\/({dest_port}\d{1,100}))?""",
  ]
}
```