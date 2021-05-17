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
    """(\w+\s{1,100}\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({host}\S+)\s""",
    """Connection Status:\s{1,100}({action}({outcome}[^\s]{1,2000}).+?)\.\s{1,100}Type""",
    """Source:\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
}
```