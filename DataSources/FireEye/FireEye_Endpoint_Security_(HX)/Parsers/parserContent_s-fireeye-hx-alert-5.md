#### Parser Content
```Java
{
Name = s-fireeye-hx-alert-5
    Vendor = FireEye
    Product = FireEye Endpoint Security (HX)
    Lms = Splunk
    DataType = "file-write"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"hostname":""", """"event_at":""", """"event_type":""", """"fileWriteEvent"""", """"fileWriteEvent/fileName":""", """"alert_id":""" ]
    Fields = [
       """"event_at":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
       """"alert_id":\s*({alert_id}\d+)""",
       """"last_poll_ip":\s*"({dest_ip}[\da-fA-F.:]+)""",
       """"event_id":\s*({event_code}\d+)""",
       """"fileWriteEvent/eventReason":\s*"({activity}[^"]+)""",
       """"fileWriteEvent/fileName":\s*"({file_name}[^"]+)""",
       """"hostname":\s*"({host}[^"]+)""",
       """"fileWriteEvent/username":\s*"(({domain}[^"\\\/]+)[\\\/]+)?({user}[^"]+)""",
       """"event_type":\s*"({event_name}[^"]+)""",
       """"fileWriteEvent\/fullPath":\s*"({file_path}[^"]+)""",
       """"fileWriteEvent\/process":\s*"({process}[^"]+)"""
    ]      
  }
```