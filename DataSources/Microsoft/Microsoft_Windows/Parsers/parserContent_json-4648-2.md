#### Parser Content
```Java
{
Name = json-4648-2
  DataType = "windows-account-switch"
  Conditions = ["""A logon was attempted using explicit credentials""", """Target Server Name""", """computer_name""", """event_id\":4648"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A logon was attempted using explicit credentials)""",
    """"LogonGuid\\?"{1,20}:\\?"\{({user_logon_guid}[^}]{1,2000})\}\\?"""",
    """TargetUserName\\?"{1,20}:\\?"(LOCAL SYSTEM|({account}[^\\]{1,2000}))\\?"""",
    """TargetDomainName\\?"{1,20}:\\?"(\.|({account_domain}[^\\]{1,2000}))\\?"""",
    """TargetLogonGuid\\?"{1,20}:\\?"\{({account_logon_guid}[^\\}]{1,2000})\}\\?"""",
    """TargetServerName\\?"{1,20}:\\?"({dest_host}[^\\]{1,2000})\\?"""",
    """TargetInfo\\?"{1,20}:\\?"({dest_service}[^\s:;\\]{1,2000})\\?"""",
    """IpAddress\\?"{1,20}:\\?"(?:-|(::[\w]{1,2000}:)?({src_ip}[a-fA-F:\d.]{1,2000}))\\?""""
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
  ]

```