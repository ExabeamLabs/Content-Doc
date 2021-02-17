#### Parser Content
```Java
{
Name = json-4624-2
  DataType = "windows-4624"
  Conditions = [ """An account was successfully logged on""", """Account Name""", """computer_name""", """event_id\":4624"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}An account was successfully logged on)""",
    """LogonType\\?"+:\\?"({logon_type}\d+)\\?"""",
    """TargetUserName\\?"+:\\?"({user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({domain}[^\s"\\]+)\\?"""",
    """IpAddress\\?"+:\\?"(?:-|(::[\w]+:)?({src_ip}[a-fA-F:\d.]+))\\?"""",
    """TargetUserSid\\?"+:\\?"({user_sid}[^\\]+)\\?""""
  ]
  DupFields = ["host->dest_host", "directory->process_directory"]
}
```