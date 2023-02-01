#### Parser Content
```Java
{
Name = cef-salesforce-account-switch
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """destinationServiceName =Sales Cloud""", """cat=access""", """msg=""" ]
  Fields = [
  """CreatedDate\\?=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
  """Action\\?=({activity}[^;]{1,2000})""",
  """flexString2=({event_name}[^=]{1,2000})\s\w+="""
  """CreatedBy.Email\\?=({user_email}[^;@\s]{1,2000}@[^\s;]{1,2000})"""
  """CreatedBy.Name\\?=({user}[^;]{1,2000})"""
  """suser=({account_name}[^\s]{1,2000})\s"""
  """({app}Sales Cloud)""",
  """Display\\?=({additional_info}[^"]{1,2000})"""
  ]


}
```