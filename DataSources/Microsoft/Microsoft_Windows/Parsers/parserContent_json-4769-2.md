#### Parser Content
```Java
{
Name = json-4769-2
  DataType = "windows-4769"
  Conditions = ["""A Kerberos service ticket was requested""", """Account Name""", """computer_name""", """event_id\":4769"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A Kerberos service ticket was requested)""",
    """TargetUserName\\?"+:\\?"+((({user}[^@\s\\]+?)(?:@({domain}[^\\]+))?)|({user_email}[^@\s]+?@[^\s\.]+?\.[^\s\\]+?))\\?"""",
    """TargetDomainName\\?"+:\\?"+({domain}[^\\]+)""",
    """ServiceName\\?"+:\\?"+({dest_host}[^\s\\]+)""",
    """IpAddress\\?"+:\\?"+(::[\w]+:)?({src_ip}[\da-fA-F.:]+)\\?"""",
    """Status\\?"+:\\?"+({result_code}[^\s\\]+)""",
    """TicketOptions\\?"+:\\?"+({ticket_options}[^\s\\]+)""",
    """TicketEncryptionType\\?"+:\\?"+({ticket_encryption_type}[^\s\\]+)"""
 ]
 DupFields = ["dest_host->service_name"]
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