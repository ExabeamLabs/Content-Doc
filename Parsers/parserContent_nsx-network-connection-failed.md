#### Parser Content
```Java
{
Name = nsx-network-connection-failed
  Vendor = NSX
  Product = VMware NSX
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ INET""", """ TERM """  ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) ({host}[\w\.\-]+)""",
    """\sINET\d* ({outcome}TERM)""",
    """({direction}IN|OUT)\s+({protocol}\w+)\s+(\S+\s+)?(\S+\s+)?({src_ip}[a-fA-F\d.:]+)(\/({src_port}\d+))?->({dest_ip}[a-fA-F\d.:]+)(\/({dest_port}\d+))?\s+\S+\s+({bytes_in}\d+)\/({bytes_out}\d+)""",
  ]
}
```