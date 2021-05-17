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
       """"last_poll_ip":\s{0,100}"({dest_ip}[\da-fA-F.:]{1,2000})""",
       """"event_id":\s{0,100}({event_code}\d{1,100})""",
       """"fileWriteEvent/eventReason":\s{0,100}"({activity}[^"]{1,2000})""",
       """"fileWriteEvent/fileName":\s{0,100}"({file_name}[^"]{1,2000})""",
       """"hostname":\s{0,100}"({host}[^"]{1,2000})""",
       """"fileWriteEvent/username":\s{0,100}"(({domain}[^"\\\/]{1,2000})[\\\/]{1,2000})?({user}[^"]{1,2000})""",
       """"event_type":\s{0,100}"({event_name}[^"]{1,2000})""",
       """"fileWriteEvent\/fullPath":\s{0,100}"({file_path}[^"]{1,2000})""",
       """"fileWriteEvent\/process":\s{0,100}"({process}[^"]{1,2000})"""
    ]      
  }
```