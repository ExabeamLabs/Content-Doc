#### Parser Content
```Java
{
Name = json-4648-2
  DataType = "windows-account-switch"
  Conditions = ["""A logon was attempted using explicit credentials""", """Target Server Name""", """computer_name""", """event_id\":4648"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A logon was attempted using explicit credentials)""",
    """"LogonGuid\\?"+:\\?"\{({user_logon_guid}[^}]+)\}\\?"""",
    """TargetUserName\\?"+:\\?"(LOCAL SYSTEM|({account}[^\\]+))\\?"""",
    """TargetDomainName\\?"+:\\?"(\.|({account_domain}[^\\]+))\\?"""",
    """TargetLogonGuid\\?"+:\\?"\{({account_logon_guid}[^\\}]+)\}\\?"""",
    """TargetServerName\\?"+:\\?"({dest_host}[^\\]+)\\?"""",
    """TargetInfo\\?"+:\\?"({dest_service}[^\s:;\\]+)\\?"""",
    """IpAddress\\?"+:\\?"(?:-|(::[\w]+:)?({src_ip}[a-fA-F:\d.]+))\\?""""
  ]
  DupFields=[ "host->dest_host","src_host_windows->src_host" ]
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