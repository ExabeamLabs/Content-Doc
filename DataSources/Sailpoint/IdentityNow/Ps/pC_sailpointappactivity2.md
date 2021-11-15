#### Parser Content
```Java
{
Name = sailpoint-app-activity-2
  Conditions = [ """"type": "USER_MANAGEMENT"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"info":\s{0,100}"(NONE|({additional_info}[^",]{1,2000}))""""
  ]

sailpoint-activity-1 {
  Vendor = Sailpoint
  Product = IdentityNow
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"created":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"hostName":\s{0,100}"(\d{1,100}|({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}[^",]{1,2000}))"""",
    """"ipAddress":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"action":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"type":\s{0,100}"({activity_type}[^",]{1,2000})"""",
    """"actor":[^\}]{1,2000}?"name":\s{0,100}"(Not Available|unknown|({user_fullname}[^\s",]{1,2000}(|,)\s[^\s",]{1,2000})|({user}[^\s",]{1,2000}))"""",
    """"technicalName":\s{0,100}"({event_name}[^",]{1,2000})"""",
    """"status":\s{0,100}"({outcome}[^",]{1,2000})"""",
    """"sourceName":\s{0,100}"({app}[^",]{1,2000})""""
  
}
```