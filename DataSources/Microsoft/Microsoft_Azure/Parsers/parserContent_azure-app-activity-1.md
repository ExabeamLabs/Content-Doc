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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"result":"({outcome}[^"]{1,2000})"""",
    """"activityDisplayName":"({event_name}[^"]{1,2000})"""",
    """"operationType":"({activity}[^"]{1,2000})"""",
    """"user":\{"id":"({user_id}[^"]{1,2000})"""",
    """"initiatedBy"[^]]{1,2000}"userPrincipalName":"({user_email}({user}[^@"]{1,2000})@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """targetResources[^}]{1,2000}"userPrincipalName":"({target_user}[^@"]{1,2000})""",
    """"resourceId":"({object}[^"]{1,2000})"""",
    """"newValue":"\[({additional_info}\{[\\]?"PhoneNumber[^]]{1,2000})"""
  ]
}
```