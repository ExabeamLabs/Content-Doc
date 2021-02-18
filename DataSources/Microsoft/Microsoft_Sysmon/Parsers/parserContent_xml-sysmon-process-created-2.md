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
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>10</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name=""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<Computer>({host}({dest_host}[\w\-]+)[^<]*)</Computer>""",
    """<Data Name='User'>(({domain}[^\\<]+?)\\)?({user}[^<]+)</Data>""",
    """<Security UserID='({user_sid}[^']+)'/>""",
    """<Data Name='Hashes'>.*?MD5=({md5}[A-F0-9a-f]+).*?</Data>""",
    """(?i)<Data Name='SourceProcessGuid'>\{({process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='SourceProcessId'>({pid}\d+)</Data>""",
    """(?i)<Data Name='TargetProcessGuid'>\{({target_process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='TargetProcessId'>({target_pid}\d+)</Data>""",
    """<Data Name='CommandLine'>({command_line}[^<]+?)\s*</Data>""",
    """<Data Name='SourceImage'>({parent_process}(({parent_directory}[^<]*)\\+)?({parent_process_name}[^<]+?))</Data>""",
    """<Data Name='TargetImage'>({process}(({directory}[^<]*)\\+)?({process_name}[^<]+?))</Data>""",
    """<Data Name='GrantedAccess'>({outcome}[^<]+)</Data>""",
    """<EventID>({event_code}\d+)"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```