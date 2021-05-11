#### Parser Content
```Java
{
Name = json-4648-2
  DataType = "windows-account-switch"
  Conditions = ["""A logon was attempted using explicit credentials""", """Target Server Name""", """computer_name""", """event_id\":4648"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A logon was attempted using explicit credentials)""",
    """"LogonGuid\\?"{1,20}:\\?"\{({user_logon_guid}[^}]+)\}\\?"""",
    """TargetUserName\\?"{1,20}:\\?"(LOCAL SYSTEM|({account}[^\\]+))\\?"""",
    """TargetDomainName\\?"{1,20}:\\?"(\.|({account_domain}[^\\]+))\\?"""",
    """TargetLogonGuid\\?"{1,20}:\\?"\{({account_logon_guid}[^\\}]+)\}\\?"""",
    """TargetServerName\\?"{1,20}:\\?"({dest_host}[^\\]+)\\?"""",
    """TargetInfo\\?"{1,20}:\\?"({dest_service}[^\s:;\\]+)\\?"""",
    """IpAddress\\?"{1,20}:\\?"(?:-|(::[\w]+:)?({src_ip}[a-fA-F:\d.]+))\\?""""
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