#### Parser Content
```Java
{
Name = json-4624-2
  DataType = "windows-4624"
  Conditions = [ """An account was successfully logged on""", """Account Name""", """computer_name""", """event_id\":4624"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An account was successfully logged on)""",
    """LogonType\\?"{1,20}:\\?"({logon_type}\d{1,100})\\?"""",
    """TargetUserName\\?"{1,20}:\\?"({user}[^\\]+)\\?"""",
    """TargetDomainName\\?"{1,20}:\\?"({domain}[^\s"\\]+)\\?"""",
    """IpAddress\\?"{1,20}:\\?"(?:-|(::[\w]+:)?({src_ip}[a-fA-F:\d.]+))\\?"""",
    """TargetUserSid\\?"{1,20}:\\?"({user_sid}[^\\]+)\\?""""
  ]
  DupFields = ["host->dest_host", "directory->process_directory"]
}
json-windows-events-2 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """@timestamp\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """(?:winlog\.)?computer_name\\?"{1,20}:\\?"{1,20}({host}[^\\]+)""",
    """SubjectUserName\\?"{1,20}:\\?"{1,20}(?:-|(?i)(LOCAL SYSTEM|anonymous logon|LOCAL SERVICE|SYSTEM)|({user}[^\\]+))\\?"""",
    """SubjectUserSid\\?"{1,20}:\\?"{1,20}({user_sid}[^\\]+)\\?"""",
    """SubjectDomainName\\?"{1,20}:\\?"{1,20}(|-|NT Service|NT AUTHORITY|({domain}[^\\]+))\\?"""",
    """SubjectLogonId\\?"{1,20}:\\?"{1,20}({logon_id}[^\\]+)\\?"""",
    """event_id\\?"{1,20}:({event_code}\d{1,100})""",
    """ProcessName\\?"{1,20}:\\?"{1,20}(?:|-|({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/":;\s]+?)))\\?"""",
    """WorkstationName\\?"{1,20}:\\?"{1,20}(?:-|({src_host_windows}[^\s\\]+))\\?"""",
    """Status\\?"{1,20}:\\?"{1,20}({result_code}[^\\]+)\\?"""",
    """ProcessId\\?"{1,20}:\\?"{1,20}({process_id}[^:\\]+?)\\?"""",
    """LogonProcessName\\?"{1,20}:\\?"{1,20}({auth_process}[^\s\\]+)\s{0,100}\\?"""",
    """AuthenticationPackageName\\?"{1,20}:\\?"{1,20}({auth_package}[^\s\\]+)\\?""""
  ]

```