#### Parser Content
```Java
{
Name = json-microsoft-app-activity-32
  Vendor = Microsoft
  Product = Office 365
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions= [ """"Application": """, """"DeviceName": """, """"Operation": "SensitivityLabelUpdated"""", """"SensitivityLabelEventData": """]
  Fields = [
    """"CreationTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""", 
    """"Application":\s{0,100}"({app}[^"]{1,2000})"""",
    """"ClientIP":\s{0,100}"({src_ip}[^"]{1,2000})"""",
    """"UserId":\s{0,100}"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """"DeviceName":\s{0,100}"({src_host}[^"]{1,2000})""",
    """"Operation":\s{0,100}"({activity}[^"]{1,2000})"""",
    """"Platform":\s{0,100}"({os}[^"]{1,2000})"""",
    """"ObjectId":"({object_id}[^"]{1,2000})"""",
    """"LabelEventType":\s{0,100}({event_code}\d{1,2000})"""",
    """"SensitivityLabelEventData":\s{0,100}\{({additional_info}[^\}]{1,2000})\}"""
  ]


}
```