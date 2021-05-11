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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """ radiusd\[\d{1,100}\]:\s{0,100}\(\d{1,100}\) Login ({outcome}OK):\s{0,100}\[({user}[^\s\/\]]+)\] \(from client ({src_host}[\w\-.]+) port ({src_port}\d{1,100})""",
  ]
}
```