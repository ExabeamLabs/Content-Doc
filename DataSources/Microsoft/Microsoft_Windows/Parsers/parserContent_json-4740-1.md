#### Parser Content
```Java
{
Name = json-4740-1
  DataType = "windows-account-lockout"
  Conditions = [ """Account That Was Locked Out""", """event_id\":4740""", """computer_name""" ]
  Fields = ${WinParserTemplates.json-windows-events-2.Fields}[
    """SubjectUserName\\?"+:\\?"({caller_user}[^\\]+)\\?"""",
    """SubjectDomainName\\?"+:\\?"({caller_domain}[^\\]+)\\?"""",
    """SubjectLogonId\\?"+:\\?"({logon_id}[^\\]+)\\?"""",
    """TargetSid\\?"+:\\?"({user_sid}[^\\]+)\\?"""",
    """TargetUserName\\?"+:\\?"({user}[^\\]+)\\?"""",
    """TargetDomainName\\?"+:\\?"({src_host}[^\s\\]+)\\?""""
  ]
  DupFields=[ "host->dest_host", "caller_domain->domain" ]
}
```