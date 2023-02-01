#### Parser Content
```Java
{
Name = cef-windows-ds-access-5137
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName =Azure""", """EventID":5137""", """"Activity":"5137 - A directory service object was created""" ]
  Fields = [
  """({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,3}Z)"""
  """"Computer":"({host}[\w\-.]{1,2000})"""
  """({event_code}5137)"""
  """({event_name}A directory service object was created)"""
  """"SubjectLogonId":"({logon_id}[^"]{1,2000})""""
  """"ManagementGroupName":"({group_name}[^"]{1,2000})""""
  """"SourceSystem":"({app}[^"]{1,2000})""""
  """"SubjectUserName":"({user}[^"]{1,2000})""""
  """"SubjectDomainName":"({domain}[^"]{1,2000})""""
  """"SubjectUserSid":"({user_sid}[^"]{1,2000})""""
  """"TenantId":"({tenant_id}[^"]{1,2000})""""
  """<Data Name\\?=\\?"ObjectClass\\?">({object_class}[^<]{1,2000}?)<\/Data>"""
  """<Data Name\\?=\\?"ObjectDN\\?">({object_dn}[^<]{1,2000}?)<\/Data>"""
  ]


}
```