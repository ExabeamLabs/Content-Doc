#### Parser Content
```Java
{
Name = wls-4688
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "windows-process-created"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """LogType="WLS"""", """EventID="4688"""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="+({dest_host}[^"]+)"""",
      """EventID="+({event_code}[^"]+)"""",
      """NewProcessName="+({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
      """NewProcessName="+({path}.+?)"""",
      """SubjectUserName="+(?=\w)({user}[^"]+)"""",
      """SubjectDomainName="+(?=\w)({domain}[^"]+)"""",
      """SubjectLogonId="+({logon_id}[^"]+)"""",
      """ProcessId="+({parent_process_guid}[^"]+)"""",
      """NewProcessId="+({process_guid}[^"]+)"""",
      """CommandLine="+({command_line}[^"]+)"""",
      """CommandLine="+(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s*(?:\\*[\w.\-]+)?\s*create\s*({service_name}.+?))\s+binPath= ({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""
    ]
    DupFields = [ "process_guid->pid","directory->process_directory" ]
  }
```