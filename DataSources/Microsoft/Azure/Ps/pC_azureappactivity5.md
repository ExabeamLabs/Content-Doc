#### Parser Content
```Java
{
Name = azure-app-activity-5
  Conditions = [ """"ActivityDisplayName":"Delete user"""", """"OperationName":"Delete user"""", """"ActivityDateTime":"""", """"ResourceId":"""" ]
  
 
azure-app-activity-2 {
    Vendor = Microsoft
    Product = Azure
    Lms = Splunk
    DataType = "app-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"ActivityDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z)"""",
      """"Result":"({outcome}[^"]{1,2000})"""",
      """"ActivityDisplayName":"({event_name}[^"]{1,2000})"""",
      """"ResourceId":"({object}[^"]{1,2000})"""",
      """"value\\":\\"({user_agent}[^"]{1,2000}?)\\?",\\"key\\":\\"User-Agent\\"""",
      """"key\\":\\"User-Agent\\",\\"value\\":\\"({user_agent}[^"]{1,2000}?)\\?"""",
      """"InitiatedBy":"\{\\"user\\":\{[^\}]{1,2000}"userPrincipalName\\":\\"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000}?)\\?"""",
      """CallerIpAddress":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
      """"InitiatedBy":"\{\\"user\\":\{[^\}]{1,2000}"ipAddress\\":\\"({src_ip}[A-Fa-f:\d.]{1,2000}?)\\?"""",
      """"LoggedByService":"(Core Directory|({app}[^"]{1,2000}))"""",
      """TargetResources":"\[[^|]{1,2000}userPrincipalName\\":\\"(({target_user_email}[^@"]{1,2000}@[^"]{1,2000}?)|({target_user}[^"]{1,2000}?))\\?"""",
      """destinationServiceName =({app}Azure)""",
      """"app":\{[^,]{1,100},"displayName":"({app}[^"]{1,2000})""""
      """Category":"({category}[^"]{1,2000})""",
      """"Type":"({log_type}[^"]{1,2000})""",
      """"type":"({additional_info}[^"]{1,2000})""",
      """"Resource":"({resource}[^"]{1,2000})""",

    ]
   DupFields = [ "event_name->activity" 
}
```