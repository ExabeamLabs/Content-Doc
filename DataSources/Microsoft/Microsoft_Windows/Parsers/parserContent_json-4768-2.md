#### Parser Content
```Java
{
Name = json-4768-2
  DataType = "windows-4768"
  Conditions = ["""A Kerberos authentication ticket (TGT) was requested""", """Account Name""", """computer_name""", """event_id\":4768"""]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
    """TargetUserName\\?"+:\\?"(?:-|(?i)(system|anonymous logon|LOCAL SERVICE|LOCAL SYSTEM)|({user}[^\\]+))\\?"""",
    """IpAddress\\?"+:\\?"(::[\w]+:)?({dest_ip}[a-fA-F:\d.]+)\\?"""",
    """Status\\?"+:\\?"({result_code}[\w\-]+)\\?"""",
    """TargetDomainName\\?"+:\\?"(?:-|({domain}[^\s\\]+?))\\?"""",
    """TargetSid\\?"+:\\?"({user_sid}[^\\]+)\\?""""
  ]
}
```