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
  Conditions = [ """<Provider Name='Microsoft-Windows-Sysmon'""", """<EventID>8</EventID>""", """<Channel>Microsoft-Windows-Sysmon/Operational</Channel>""", """<Data Name=""" ]
  Fields = [
    """<Data Name='UtcTime'>({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d)</Data>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """<Computer>({host}.+?)</Computer>""",
    """<Data Name='User'>(({domain}[^\\<]+?)\\)?({user}.+?)</Data>""",
    """<Security UserID='({user_sid}.+?)'/>""",
    """<Data Name='Hashes'>.*?MD5=({md5}[A-F0-9a-f]+).*?</Data>""",
    """(?i)<Data Name='SourceProcessGuid'>\{({process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='SourceProcessId'>({pid}\d+)</Data>""",
    """(?i)<Data Name='TargetProcessGuid'>\{({target_process_guid}[A-F0-9a-f-]+)\}</Data>""",
    """<Data Name='TargetProcessId'>({target_pid}\d+)</Data>""",
    """<Data Name='CommandLine'>({command_line}.+?)\s*</Data>""",
    """<Data Name='SourceImage'>({path}(({directory}[^<]*)\\+)?({process_name}.+?))</Data>""",
    """<Data Name='TargetImage'>({target_path}(({target_directory}[^<]*)\\+)?({target_process_name}.+?))</Data>""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory","path->process" ]
}
```