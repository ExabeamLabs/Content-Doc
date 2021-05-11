#### Parser Content
```Java
{
Name = azure-app-activity-1
  Vendor = Microsoft
  Product = Microsoft Azure 
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [""""activityDisplayName":"Update user"""", """"operationType":"Update"""", """"activityDateTime":"""", """StrongAuthenticationUserDetails""", """VoiceOnlyPhoneNumber""" ]
  Fields = [
    """"activityDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}[+-]\d\d:\d\d)"""",
    """exabeam_host=({host}[^\s]+)""",
    """"result":"({outcome}[^"]+)"""",
    """"activityDisplayName":"({event_name}[^"]+)"""",
    """"operationType":"({activity}[^"]+)"""",
    """"user":\{"id":"({user_id}[^"]+)"""",
    """"initiatedBy"[^]]+"userPrincipalName":"({user_email}({user}[^@"]+)@[^\."]+\.[^"]+)"""",
    """targetResources[^}]+"userPrincipalName":"({target_user}[^@"]+)""",
    """"resourceId":"({object}[^"]+)"""",
    """"newValue":"\[({additional_info}\{[\\]?"PhoneNumber[^]]+)"""
  ]
}
```