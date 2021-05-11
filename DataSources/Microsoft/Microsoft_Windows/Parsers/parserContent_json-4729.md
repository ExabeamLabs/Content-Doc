#### Parser Content
```Java
{
Name = json-4729
  DataType = "windows-member-removed"
  Conditions = [ """Security ID:""", """Logon ID:""", """A member was removed from a security-enabled""", """raw""", """event_id\":4729""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A member was removed from a security-enabled [\w\s]+ group)""",
    """A member was removed from a security-enabled\s{0,100}({group_type}[^\s]+)\s{1,100}group""",
    """MemberSid\\?"{1,20}:\\?"{1,20}({account_id}[^\\]+)\\?"""",
    """MemberName\\?"{1,20}:\\?"{1,20}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-\\]+?))\\?"""",
    """TargetSid\\?"{1,20}:\\?"{1,20}({group_id}[^\\]+)\\?"""",
    """TargetUserName\\?"{1,20}:\\?"{1,20}({group_name}[^\\]+)\\?"""",
    """TargetDomainName\\?"{1,20}:\\?"{1,20}({group_domain}[^\\]+)\\?""""
  ]
  DupFields = [ "host->dest_host" ]
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