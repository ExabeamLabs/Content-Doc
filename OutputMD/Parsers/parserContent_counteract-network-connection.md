#### Parser Content
```Java
{
Name = counteract-network-connection
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Connection has been established:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\w+\s+\d+ \d+:\d+:\d+)\s+({host}\S+)\s""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """from\[({src_ip}[a-fA-F\d.:]+)\]\s+to\[({dest_ip}[a-fA-F\d.:]+)\]""",
  ]
}
```