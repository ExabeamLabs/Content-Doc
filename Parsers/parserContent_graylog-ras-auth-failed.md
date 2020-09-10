#### Parser Content
```Java
{
Name = graylog-ras-auth-failed
  Vendor = Radius
  Product = Radius
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ radiusd[""", """ Login incorrect """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """ radiusd\[\d+\]:\s*\(\d+\) Login ({outcome}incorrect) \(({failure_reason}[^\)]+)\):\s*\[({user}[^\s\/\]]+)[^\]]*\] \(from client ({src_host}[\w\-.]+) port ({src_port}\d+)\) ({account}[^\s]+)""",
  ]
}
```