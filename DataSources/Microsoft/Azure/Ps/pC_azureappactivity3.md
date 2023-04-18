#### Parser Content
```Java
{
Name = azure-app-activity-3
  Conditions = [ """"ActivityDisplayName":"Add user"""", """"OperationName":"Add user"""", """"ActivityDateTime":"""", """"ResourceId":"""" ]
 
azure-app-activity-2 {
    Vendor = Microsoft
    Product = Azure
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"ActivityDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)"""",
      """"Result":"({outcome}[^"]{1,2000})"""",
      """"ActivityDisplayName":"({event_name}[^"]{1,2000})"""",
      """"AADOperationType":"({activity}[^"]{1,2000})"""",
      """"ResourceId":"({object}[^"]{1,2000})"""",
      """"value\\":\\"({user_agent}[^"]{1,2000}?)\\?",\\"key\\":\\"User-Agent\\"""",
      """"key\\":\\"User-Agent\\",\\"value\\":\\"({user_agent}[^"]{1,2000}?)\\?"""",
      """"InitiatedBy":"\{\\"user\\":\{[^\}]{1,2000}"userPrincipalName\\":\\"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000}?)\\?"""",
      """"InitiatedBy":"\{\\"user\\":\{[^\}]{1,2000}"ipAddress\\":\\"({src_ip}[A-Fa-f:\d.]{1,2000}?)\\?"""",
      """"LoggedByService":"({app}[^"]{1,2000})"""",
      """TargetResources":"\[[^|]{1,2000}userPrincipalName\\":\\"({target_user}[^"]{1,2000}?)\\?""""
    
}
```