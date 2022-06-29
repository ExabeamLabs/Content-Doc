#### Parser Content
```Java
{
Name = json-4724-2
  Vendor = Microsoft
  Product = Windows
  Lms = Syslog
  DataType = "windows-password-reset"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"EventID":"4724"""", """An attempt was made to reset an account's password."""", """"SubjectUserName":"""", """"TargetSid":"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)""",
    """"Computer":"({host}[^"]{1,2000})"""",
    """"EventID":"({event_code}\d{1,100})"""",
    """({event_name}An attempt was made to reset an account's password)""",
    """"SubjectAccount":"(({domain}[^"\\]{1,2000})\\{1,20})?({user}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"TargetDomainName":"({target_domain}[^"]{1,2000})"""",
    """"TargetSid":"({target_user_sid}[^"]{1,2000})"""",
    """"TargetUserName":"({target_user}[^"]{1,2000})""""
  ]
  DupFields = [ "host->dest_host" ]


}
```