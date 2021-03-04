#### Parser Content
```Java
{
Name = graylog-ras-auth-successful
  Vendor = Radius
  Product = Radius
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ radiusd[""", """ Login OK""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """ radiusd\[\d+\]:\s*\(\d+\) Login ({outcome}OK):\s*\[({user}[^\s\/\]]+)\] \(from client ({src_host}[\w\-.]+) port ({src_port}\d+)""",
  ]
}
```