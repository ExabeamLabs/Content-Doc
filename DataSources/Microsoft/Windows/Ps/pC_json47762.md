#### Parser Content
```Java
{
Name = json-4776-2
  DataType = "windows-4776"
  Conditions = ["""attempted to validate the credentials for an account""", """Authentication Package""", """computer_name""", """event_id\":4776"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
    """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
    """Workstation\\?"{1,20}:\\?"{1,20}({dest_host}[^\\]{1,2000})\\?"""",
    """TargetUserName\\?"{1,20}:\\?"{1,20}((({user}[^@\s\\]{1,2000}?)(?:@({domain}[^\\]{1,2000}))?)|({user_email}[^@\s]{1,2000}?@[^\s\.]{1,2000}?\.[^\s\\]{1,2000}?))\\?""""
  ]

json-windows-events-2 = {
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """@timestamp\\?"{1,20}:\\?"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """(?:winlog\.)?computer_name\\?"{1,20}:\\?"{1,20}({host}[^\\]{1,2000})""",
    """SubjectUserName\\?"{1,20}:\\?"{1,20}(?:-|(?i)(LOCAL SYSTEM|anonymous logon|LOCAL SERVICE|SYSTEM)|({user}[^\\]{1,2000}))\\?"""",
    """SubjectUserSid\\?"{1,20}:\\?"{1,20}({user_sid}[^\\]{1,2000})\\?"""",
    """SubjectDomainName\\?"{1,20}:\\?"{1,20}(|-|NT Service|NT AUTHORITY|({domain}[^\\]{1,2000}))\\?"""",
    """SubjectLogonId\\?"{1,20}:\\?"{1,20}({logon_id}[^\\]{1,2000})\\?"""",
    """event_id\\?"{1,20}:({event_code}\d{1,100})""",
    """ProcessName\\?"{1,20}:\\?"{1,20}(?:|-|({process}({directory}(?:[^";]{1,2000})?[\\\/])?({process_name}[^\\\/":;\s]{1,2000}?)))\\?"""",
    """WorkstationName\\?"{1,20}:\\?"{1,20}(?:-|({src_host_windows}[^\s\\]{1,2000}))\\?"""",
    """Status\\?"{1,20}:\\?"{1,20}({result_code}[^\\]{1,2000})\\?"""",
    """ProcessId\\?"{1,20}:\\?"{1,20}({process_id}[^:\\]{1,2000}?)\\?"""",
    """LogonProcessName\\?"{1,20}:\\?"{1,20}({auth_process}[^\s\\]{1,2000})\s{0,100}\\?"""",
    """AuthenticationPackageName\\?"{1,20}:\\?"{1,20}({auth_package}[^\s\\]{1,2000})\\?""""
  
}
```