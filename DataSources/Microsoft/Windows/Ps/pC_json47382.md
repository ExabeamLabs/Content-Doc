#### Parser Content
```Java
{
Name = json-4738-2
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "account-modification"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"SubjectUserName":"""", """"A user account was changed""", """"OperationName":"MICROSOFT.AAD/DomainServices/Events/Security/4738"""" ]
  Fields = [
    """({event_name}A user account was changed)""",
    """({event_code}4738)""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"Category"{1,20}:"{1,20}({category}[^"]{1,2000})"""",
    """"TargetSid":"({target_sid}[^"]{1,2000})""""
 ]


}
```