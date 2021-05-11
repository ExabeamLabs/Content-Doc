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
       """"Message":\s{0,100}"({activity}[^:]+)""",
       """"Image":\s{0,100}"[\\?]*({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
       """"Hostname":\s{0,100}"({host}[^"]+)""",
       """"UtcTime":\s{0,100}"({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
       """"UserID":\s{0,100}"({user_sid}[^"]+)""",
       """"ProcessGuid":\s{0,100}"({process_guid}[^"]+)""",
       """"ProcessID":\s{0,100}({process_id}\d{1,100})""",
       """"Task":\s{0,100}({event_code}\d{1,100})""",
       """"RuleName":\s{0,100}"(-|({accesses}[^"]+))""",
       """"AccountName":\s{0,100}"((?i)SYSTEM|({user}[^"]+))""",
       """"Domain":\s{0,100}"((?i)NT AUTHORITY|({domain}[^"]+))""",
    ]      
    DupFields = [ "file_path->process", "host->dest_host", "file_name->process_name", "activity->event_name" ]
}
```