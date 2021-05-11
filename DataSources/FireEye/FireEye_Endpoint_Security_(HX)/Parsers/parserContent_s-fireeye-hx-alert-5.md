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
       """"event_at":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
       """"alert_id":\s{0,100}({alert_id}\d{1,100})""",
       """"last_poll_ip":\s{0,100}"({dest_ip}[\da-fA-F.:]+)""",
       """"event_id":\s{0,100}({event_code}\d{1,100})""",
       """"fileWriteEvent/eventReason":\s{0,100}"({activity}[^"]+)""",
       """"fileWriteEvent/fileName":\s{0,100}"({file_name}[^"]+)""",
       """"hostname":\s{0,100}"({host}[^"]+)""",
       """"fileWriteEvent/username":\s{0,100}"(({domain}[^"\\\/]+)[\\\/]+)?({user}[^"]+)""",
       """"event_type":\s{0,100}"({event_name}[^"]+)""",
       """"fileWriteEvent\/fullPath":\s{0,100}"({file_path}[^"]+)""",
       """"fileWriteEvent\/process":\s{0,100}"({process}[^"]+)"""
    ]      
  }
```