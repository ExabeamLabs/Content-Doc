#### Parser Content
```Java
{
Name = s-fireeye-hx-alert-4
    Vendor = FireEye
    Product = FireEye Endpoint Security (HX)
    Lms = Splunk
    DataType = "process-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"event_at":""", """"event_type":""", """"processEvent"""", """"processEvent/pid":""", """"processEvent/process":""", """"alert_id":""" ]
    Fields = [
       """"event_at":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
       """"alert_id":\s*({alert_id}\d+)""",
       """"processEvent/eventType":\s*"({event_name}[^"]+)""",
       """"processEvent/processCmdLine":\s*"({command_line}.+?)"\}?,""",
       """"last_poll_ip":\s*"({dest_ip}[\da-fA-F.:]+)"""",
       """"hostname":\s*"({host}[^"]+)""",
       """"processEvent/md5":\s*"({md5}[^"]+)""",
       """"processEvent/process":\s*"({process_name}[^"]+)""",
       """"processEvent/username":\s*"(({domain}[^"\\\/]+)[\\\/]+)?({user}[^"]+)"""
       """"event_type":\s*"({alert_name}[^"]+)"""
    ]      
    DupFields = ["alert_name->alert_type"]
}
```