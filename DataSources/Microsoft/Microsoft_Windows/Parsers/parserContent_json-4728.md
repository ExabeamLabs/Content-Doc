#### Parser Content
```Java
{
Name = json-4728
  DataType = "windows-member-added"
  Conditions = [ """A member was added to a security-enabled""", """event_id\":4728""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """A member was added to a security-enabled ({group_type}\w+) group""",
    """MemberName\\?"+:\\?"+(-|({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-\\]+?)))\\?"""",
    """MemberSid\\?"+:\\?"+({account_id}[^\\]+)\\?"""",
    """TargetSid\\?"+:\\?"+({group_id}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"+({group_name}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"+({group_domain}[^\\]+)\\?""""
  ]
  DupFields = [ "host->dest_host" ]
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