#### Parser Content
```Java
{
Name = xml-sysmon-process-created-1
  Vendor = Microsoft
  Product = Microsoft Sysmon
  Lms = Splunk
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """<Provider Name ='Microsoft-Windows-Sysmon'""", """<EventID>8</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name =""" ]
  Fields = [
    """<Data Name ='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Data Name ='User'>(({domain}[^\\<]{1,2000}?)\\)?({user}.+?)</Data>""",
    """<Security UserID='({user_sid}.+?)'/>""",
    """<Data Name ='Hashes'>.*?MD5=({md5}[A-F0-9a-f]{1,2000}).*?</Data>""",
    """(?i)<Data Name ='SourceProcessGuid'>\{({process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name ='SourceProcessId'>({pid}\d{1,100})</Data>""",
    """(?i)<Data Name ='TargetProcessGuid'>\{({target_process_guid}[A-F0-9a-f-]{1,2000})\}</Data>""",
    """<Data Name ='TargetProcessId'>({target_pid}\d{1,100})</Data>""",
    """<Data Name ='CommandLine'>({command_line}.+?)\s{0,100}</Data>""",
    """<Data Name ='SourceImage'>({path}(({directory}[^<]{0,2000})\\+)?({process_name}.+?))</Data>""",
    """<Data Name ='TargetImage'>({target_path}(({target_directory}[^<]{0,2000})\\+)?({target_process_name}.+?))</Data>""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory","path->process" ]


}
```