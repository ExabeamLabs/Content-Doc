#### Parser Content
```Java
{
Name = cef-windows-account-4720
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-account-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """A user account was created""", """destinationServiceName =Azure""" ]
  Fields = [
  """({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,8}Z)"""
  """({event_name}A user account was created)""",
  """"SamAccountName":"({user}[^"]{1,2000})""""
  """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
  """"Category":"({category}[^"]{1,2000})"""
  """({event_code}4720)"""
  """"TargetSid":"{1,20}({target_user_sid}[^"]{1,2000})"""
  """"UserPrincipalName":"({user_email}[^"\s@]{1,2000}@[^"\s@]{1,2000}?)""""
  """"SubjectLogonId":"({logon_id}[^\s"]{1,2000})""",
  """"TargetUserName":"({account_name}[^"]{1,2000})"""
  """"TargetDomainName":"({account_domain}[^"]{1,2000})"""
  ]
  

}
```