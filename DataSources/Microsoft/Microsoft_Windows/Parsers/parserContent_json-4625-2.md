#### Parser Content
```Java
{
Name = json-4625-2
  DataType = "windows-failed-logon"
  Conditions = ["""An account failed to log on""", """Failure Reason""", """event_id\":4625""", """computer_name"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An account failed to log on)""",
    """SubjectUserName\\?"{1,20}:\\?"(?:-|LOCAL SYSTEM|({caller_user}[^\\]+))\\?"""",
    """SubjectDomainName\\?"{1,20}:\\?"(?:-|NT AUTHORITY|({caller_domain}[^\\]+))\\?"""",
    """TargetUserSid\\?"{1,20}:\\?"({user_sid}[^\\]+)\\?"""",
    """TargetUserName\\?"{1,20}:\\?"{1,20}(?:-|(?i)(system|anonymous logon|LOCAL SERVICE|LOCAL SYSTEM)|((({user}[^@\s\\]+?)(?:@({domain}[^\\]+))?)|({user_email}[^@\s]+?@[^\s\.]+?\.[^\s\\]+?)))\\?"""",
    """TargetDomainName\\?"{1,20}:\\?"(?:-|\.|NT AUTHORITY| |({domain}[^\s\\]+?))\\?"""",
    """IpAddress\\?"{1,20}:\\?"(?:-|(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  ]
  DupFields=[ "host->dest_host","src_host_windows->src_host" ]
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