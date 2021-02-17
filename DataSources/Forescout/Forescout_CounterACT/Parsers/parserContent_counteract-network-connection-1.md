#### Parser Content
```Java
{
Name = counteract-network-connection-1
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """]: Log: Connection Status. Details: """,""" Connection Status: ""","""Vendor:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """(\w+\s+\d+ \d+:\d+:\d+)\s+({host}\S+)\s""",
    """Connection Status:\s+({action}({outcome}[^\s]+).+?)\.\s+Type""",
    """Source:\s+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```