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
    """"Host(N|n)ame":"({host}[^"]{1,2000})"""",
    """"{1,20}EventTime"{1,20}:"{1,20}({time}\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"{1,20}""",
    """"SeverityValue":({severity}[^,]{1,2000})"""", 
    """"TargetUserName":"({target_user}[^"]{1,2000})"""",
    """"TargetDomainName":"({target_domain}[^"]{1,2000})"""",
    """"TargetSid":"({target_sid}[^"]{1,2000})"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"{1,20}Category"{1,20}:"{1,20}({category}[^"]{1,2000})"{1,20}""",
    """"{1,20}Message"{1,20}:"{1,20}({additional_info}[^"]{1,2000})"{1,20}""",
    """"{1,20}EventType"{1,20}:"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
 ] 
}
```