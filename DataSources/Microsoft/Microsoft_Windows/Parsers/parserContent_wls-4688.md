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
      """Computer="{1,20}({dest_host}[^"]+)"""",
      """EventID="{1,20}({event_code}[^"]+)"""",
      """NewProcessName="{1,20}({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
      """NewProcessName="{1,20}({path}.+?)"""",
      """SubjectUserName="{1,20}(?=\w)({user}[^"]+)"""",
      """SubjectDomainName="{1,20}(?=\w)({domain}[^"]+)"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]+)"""",
      """ProcessId="{1,20}({parent_process_guid}[^"]+)"""",
      """NewProcessId="{1,20}({process_guid}[^"]+)"""",
      """CommandLine="{1,20}({command_line}[^"]+)"""",
      """CommandLine="{1,20}(|-|(sc|((?:[^"]+)?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]+)?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""
    ]
    DupFields = [ "process_guid->pid","directory->process_directory" ]
  }
```