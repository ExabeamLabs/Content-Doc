#### Parser Content
```Java
{
Name = xml-sysmon-process-created-2
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """<Provider Name ='Microsoft-Windows-Sysmon'""", """<EventID>10</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name =""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Data Name ='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<Computer>({host}({dest_host}[\w\-]{1,2000})[^<]{0,2000})</Computer>""",
    """<Data Name ='User'>(({domain}[^\\<]{1,2000}?)\\)?({user}[^<]{1,2000})</Data>""",
    """<Security UserID='({user_sid}[^']{1,2000})'/>""",
    """<Data Name ='Hashes'>.*?MD5=({md5}[A-F0-9a-f]{1,2000}).*?</Data>""",
    """(?i)<Data Name ='SourceProcessGuid'>\{({process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name ='SourceProcessId'>({pid}\d{1,100})</Data>""",
    """(?i)<Data Name ='TargetProcessGuid'>\{({target_process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name ='TargetProcessId'>({target_pid}\d{1,100})</Data>""",
    """<Data Name ='CommandLine'>({command_line}[^<]{1,2000}?)\s{0,100}</Data>""",
    """<Data Name ='SourceImage'>({parent_process}(({parent_directory}[^<]{0,2000})\\+)?({parent_process_name}[^<]{1,2000}?))</Data>""",
    """<Data Name ='TargetImage'>({process}(({directory}[^<]{0,2000})\\+)?({process_name}[^<]{1,2000}?))</Data>""",
    """<Data Name ='GrantedAccess'>({outcome}[^<]{1,2000})</Data>""",
    """<EventID>({event_code}\d{1,100})"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```