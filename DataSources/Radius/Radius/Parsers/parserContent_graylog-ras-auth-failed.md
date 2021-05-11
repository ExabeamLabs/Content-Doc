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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """ radiusd\[\d{1,100}\]:\s{0,100}\(\d{1,100}\) Login ({outcome}incorrect) \(({failure_reason}[^\)]+)\):\s{0,100}\[({user}[^\s\/\]]+)[^\]]*\] \(from client ({src_host}[\w\-.]+) port ({src_port}\d{1,100})\) ({account}[^\s]+)""",
  ]
}
```