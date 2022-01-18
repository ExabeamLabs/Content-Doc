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
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """Computer="{1,20}({dest_host}[^"]{1,2000})"""",
      """EventID="{1,20}({event_code}[^"]{1,2000})"""",
      """NewProcessName ="{1,20}({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""",
      """NewProcessName ="{1,20}({path}.+?)"""",
      """SubjectUserName ="{1,20}(?=\w)({user}[^"]{1,2000})"""",
      """SubjectDomainName ="{1,20}(?=\w)({domain}[^"]{1,2000})"""",
      """SubjectLogonId="{1,20}({logon_id}[^"]{1,2000})"""",
      """ProcessId="{1,20}({parent_process_guid}[^"]{1,2000})"""",
      """NewProcessId="{1,20}({process_guid}[^"]{1,2000})"""",
      """CommandLine="{1,20}({command_line}[^"]{1,2000})"""",
      """CommandLine="{1,20}(|-|(sc|((?:[^"]{1,2000})?[\\\/])?sc.exe)\s{0,100}(?:\\*[\w.\-]{1,2000})?\s{0,100}create\s{0,100}({service_name}.+?))\s{1,100}binPath= ({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""
    ]
    DupFields = [ "process_guid->pid","directory->process_directory" ]
  

}
```