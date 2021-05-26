#### Parser Content
```Java
{
Name = counteract-network-connection
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Connection has been established:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({host}\S+)\s""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """from\[({src_ip}[a-fA-F\d.:]{1,2000})\](\s{1,100}to\[({dest_ip}[a-fA-F\d.:]{1,2000})\])?""",
    """({event_name}Connection has been established)"""
  ]
}
```