#### Parser Content
```Java
{
Name = json-4624-2
  DataType = "windows-4624"
  Conditions = [ """An account was successfully logged on""", """Account Name""", """computer_name""", """event_id\":4624"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An account was successfully logged on)""",
    """LogonType\\?"+:\\?"({logon_type}\d+)\\?"""",
    """TargetUserName\\?"+:\\?"({user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({domain}[^\s"\\]+)\\?"""",
    """IpAddress\\?"+:\\?"(?:-|(::[\w]+:)?({src_ip}[a-fA-F:\d.]+))\\?"""",
    """TargetUserSid\\?"+:\\?"({user_sid}[^\\]+)\\?""""
  ]
  DupFields = ["host->dest_host", "directory->process_directory"]
}
json-windows-events-2 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """@timestamp\\?"+:\\?"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """(?:winlog\.)?computer_name\\?"+:\\?"+({host}[^\\]+)""",
    """SubjectUserName\\?"+:\\?"+(?:-|(?i)(LOCAL SYSTEM|anonymous logon|LOCAL SERVICE|SYSTEM)|({user}[^\\]+))\\?"""",
    """SubjectUserSid\\?"+:\\?"+({user_sid}[^\\]+)\\?"""",
    """SubjectDomainName\\?"+:\\?"+(|-|NT Service|NT AUTHORITY|({domain}[^\\]+))\\?"""",
    """SubjectLogonId\\?"+:\\?"+({logon_id}[^\\]+)\\?"""",
    """event_id\\?"+:({event_code}\d+)""",
    """ProcessName\\?"+:\\?"+(?:|-|({process}({directory}(?:[^";]+)?[\\\/])?({process_name}[^\\\/":;\s]+?)))\\?"""",
    """WorkstationName\\?"+:\\?"+(?:-|({src_host_windows}[^\s\\]+))\\?"""",
    """Status\\?"+:\\?"+({result_code}[^\\]+)\\?"""",
    """ProcessId\\?"+:\\?"+({process_id}[^:\\]+?)\\?"""",
    """LogonProcessName\\?"+:\\?"+({auth_process}[^\s\\]+)\s*\\?"""",
    """AuthenticationPackageName\\?"+:\\?"+({auth_package}[^\s\\]+)\\?""""
  ]

```