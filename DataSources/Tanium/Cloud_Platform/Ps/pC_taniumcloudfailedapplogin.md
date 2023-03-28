#### Parser Content
```Java
{
Name = tanium-cloud-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """"type_name":"FailedCreateObject"""", """"audit_type":"authentication_audit"""", """"object_name":"""", """"audit_type":"""", """"details":"""" ]
  Fields = ${TaniumParserTemplates.tanium-cloud-app-events.Fields}[
    """"details":"({additional_info}({failure_reason}[^"\.]{1,2000})[^"]{1,2000})""""
  ]

tanium-cloud-app-events = {
  Vendor = Tanium
  Product = Cloud Platform
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"creation_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""",
    """"type_name":"({activity}[^"]{1,2000})"""",
    """"details":"User:\s(System User|({user_email}[^"@;]{1,2000}@[^";\.]{1,2000}\.[^";]{1,2000})|({user}[^;"]{1,2000}))""",
    """"details":"[^"]{0,2000}?Session ID:\s({session_id}\d{1,2000})""",
    """"domain":"(<\[)?({domain}[^>\]"]{1,2000})(\]>)?"""",
    """"audit_type":"({audit_type}[^"]{1,2000})""""
  ]
  DupFields = [ "activity->event_name" 
}
```