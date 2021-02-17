#### Parser Content
```Java
{
Name = sysmon-registry-set-1
    Vendor = Microsoft
    Product = Microsoft Sysmon
    Lms = Syslog
    DataType = "file-operations"
    TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    Conditions = [ """Microsoft-Windows-Sysmon""", """Registry value set""", """"Task":13""" ]
    Fields = [
       """"Message":\s*"({activity}[^:]+)""",
       """"Image":\s*"[\\?]*({file_path}({file_parent}[^"]*?[\\\/]+)?({file_name}[^"\\\/]+?(\.({file_ext}\w+))?))"""",
       """"Hostname":\s*"({host}[^"]+)""",
       """"UtcTime":\s*"({time}\d\d\d\d\-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
       """"UserID":\s*"({user_sid}[^"]+)""",
       """"ProcessGuid":\s*"({process_guid}[^"]+)""",
       """"ProcessID":\s*({pid}\d+)""",
       """"Task":\s*({event_code}\d+)""",
       """"RuleName":\s*"(-|({accesses}[^"]+))""",
       """"AccountName":\s*"((?i)SYSTEM|({user}[^"]+))""",
       """"Domain":\s*"((?i)NT AUTHORITY|({domain}[^"]+))""",
    ]      
    DupFields = [ "file_path->process", "host->dest_host", "file_name->process_name", "activity->event_name" ]
}
```