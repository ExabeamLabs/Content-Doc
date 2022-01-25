#### Parser Content
```Java
{
Name = sysmon-registry-set-1
    Vendor = Microsoft
    Product = Microsoft Sysmon
    Lms = Syslog
    DataType = "registry-write"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """Microsoft-Windows-Sysmon""", """Registry value set""", """"Task":13""" ]
    Fields = [
       """"Message":\s{0,100}"({activity}[^:]{1,2000})""",
       """"Image":\s{0,100}"[\\?]{0,2000}({file_path}({file_parent}[^"]{0,2000}?[\\\/]{1,2000})?({file_name}[^"\\\/]{1,2000}?(\.({file_ext}\w+))?))"""",
       """"Hostname":\s{0,100}"({host}[^"]{1,2000})""",
       """"UtcTime":\s{0,100}"({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
       """"UserID":\s{0,100}"({user_sid}[^"]{1,2000})""",
       """"ProcessGuid":\s{0,100}"({process_guid}[^"]{1,2000})""",
       """"ProcessID":\s{0,100}({process_id}\d{1,100})""",
       """"Task":\s{0,100}({event_code}\d{1,100})""",
       """"RuleName":\s{0,100}"(-|({accesses}[^"]{1,2000}))""",
       """"AccountName":\s{0,100}"((?i)SYSTEM|({user}[^"]{1,2000}))""",
       """"Domain":\s{0,100}"((?i)NT AUTHORITY|({domain}[^"]{1,2000}))""",
    ]      
    DupFields = [ "file_path->process", "host->dest_host", "file_name->process_name", "activity->event_name" ]
}
```