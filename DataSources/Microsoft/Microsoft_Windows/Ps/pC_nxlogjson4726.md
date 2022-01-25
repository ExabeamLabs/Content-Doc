#### Parser Content
```Java
{
Name = nxlog-json-4726
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-account-deleted"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4726""", """"SubjectUserSid":"""", """A user account was deleted""" ]
  Fields = [
    """"EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"Hostname":"({host}[\w\-.]{1,2000})"""",
    """({event_name}A user account was deleted)""",
    """"TargetUserName":"({target_user}[^"]{1,2000})"""",
    """"TargetDomainName":"({target_domain}[^"]{1,2000})"""",
    """"TargetSid":"({target_user_sid}[^"]{1,2000})"""",
    """"EventID":({event_code}4726)""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    ]
    DupFields=[ "host->dest_host", "target_user->account_name" ]
  

}
```