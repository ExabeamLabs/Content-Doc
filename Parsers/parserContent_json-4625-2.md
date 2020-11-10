#### Parser Content
```Java
{
Name = json-4625-2
  DataType = "windows-failed-logon"
  Conditions = ["""An account failed to log on""", """Failure Reason""", """event_id\":4625""", """computer_name"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An account failed to log on)""",
    """SubjectUserName\\?"+:\\?"(?:-|LOCAL SYSTEM|({caller_user}[^\\]+))\\?"""",
    """SubjectDomainName\\?"+:\\?"(?:-|NT AUTHORITY|({caller_domain}[^\\]+))\\?"""",
    """TargetUserSid\\?"+:\\?"({user_sid}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"+(?:-|(?i)(system|anonymous logon|LOCAL SERVICE|LOCAL SYSTEM)|((({user}[^@\s\\]+?)(?:@({domain}[^\\]+))?)|({user_email}[^@\s]+?@[^\s\.]+?\.[^\s\\]+?)))\\?"""",
    """TargetDomainName\\?"+:\\?"(?:-|\.|NT AUTHORITY| |({domain}[^\s\\]+?))\\?"""",
    """IpAddress\\?"+:\\?"(?:-|(::[\w]+:)?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"""
  ]
  DupFields=[ "host->dest_host","src_host_windows->src_host" ]
}
```