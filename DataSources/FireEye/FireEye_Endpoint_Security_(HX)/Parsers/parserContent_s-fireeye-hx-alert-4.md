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
       """"event_at":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
       """"alert_id":\s{0,100}({alert_id}\d{1,100})""",
       """"processEvent/eventType":\s{0,100}"({event_name}[^"]+)""",
       """"processEvent/processCmdLine":\s{0,100}"({command_line}.+?)"\}?,""",
       """"last_poll_ip":\s{0,100}"({dest_ip}[\da-fA-F.:]+)"""",
       """"hostname":\s{0,100}"({host}[^"]+)""",
       """"processEvent/md5":\s{0,100}"({md5}[^"]+)""",
       """"processEvent/process":\s{0,100}"({process_name}[^"]+)""",
       """"processEvent/username":\s{0,100}"(({domain}[^"\\\/]+)[\\\/]+)?({user}[^"]+)"""
       """"event_type":\s{0,100}"({alert_name}[^"]+)"""
    ]      
    DupFields = ["alert_name->alert_type"]
}
```