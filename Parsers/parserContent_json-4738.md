#### Parser Content
```Java
{
Name = json-4738
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "account-modification"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [""""EventID":4738""", """A user account was changed"""]
  Fields = [
    """({event_name}A user account was changed)""",
    """({event_code}4738)""",
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"Host(N|n)ame":"({host}[^"]+)"""",
    """"+EventTime"+:"+({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"+""",
    """"SeverityValue":({severity}[^,]+)"""", 
    """"TargetUserName":"({target_user}[^"]+)"""",
    """"TargetDomainName":"({target_domain}[^"]+)"""",
    """"TargetSid":"({target_sid}[^"]+)"""",
    """"SubjectUserSid":"({user_sid}[^"]+)"""",
    """"SubjectUserName":"({user}[^"]+)"""",
    """"SubjectDomainName":"({domain}[^"]+)"""",
    """"SubjectLogonId":"({logon_id}[^"]+)"""",
    """"+Category"+:"+({category}[^"]+)"+""",
    """"+Message"+:"+({additional_info}[^"]+)"+""",
    """"+EventType"+:"+({outcome}[^"]+)"+""",
 ] 
}
```