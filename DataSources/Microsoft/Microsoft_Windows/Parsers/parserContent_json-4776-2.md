#### Parser Content
```Java
{
Name = json-4776-2
  DataType = "windows-4776"
  Conditions = ["""attempted to validate the credentials for an account""", """Authentication Package""", """computer_name""", """event_id\":4776"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
    """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
    """Workstation\\?"{1,20}:\\?"{1,20}({dest_host}[^\\]+)\\?"""",
    """TargetUserName\\?"{1,20}:\\?"{1,20}((({user}[^@\s\\]+?)(?:@({domain}[^\\]+))?)|({user_email}[^@\s]+?@[^\s\.]+?\.[^\s\\]+?))\\?""""
  ]
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