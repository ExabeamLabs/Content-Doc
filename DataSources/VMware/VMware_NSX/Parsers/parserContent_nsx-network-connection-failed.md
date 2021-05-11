#### Parser Content
```Java
{
Name = nsx-network-connection-failed
  Vendor = VMware
  Product = VMware NSX
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ INET""", """ TERM """  ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) ({host}[\w\.\-]+)""",
    """\sINET\d{0,100} ({outcome}TERM)""",
    """({direction}IN|OUT)\s{1,100}({protocol}\w+)\s{1,100}(\S+\s{1,100})?(\S+\s{1,100})?({src_ip}[a-fA-F\d.:]+)(\/({src_port}\d{1,100}))?->({dest_ip}[a-fA-F\d.:]+)(\/({dest_port}\d{1,100}))?\s{1,100}\S+\s{1,100}({bytes_in}\d{1,100})\/({bytes_out}\d{1,100})""",
  ]
}
```