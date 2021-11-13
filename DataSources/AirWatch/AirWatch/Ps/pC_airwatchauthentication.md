#### Parser Content
```Java
{
Name = airwatch-authentication
  DataType = "authentication-successful" 
  Conditions = [ """AirWatch""", """Event Category:"Authentication"""", """Event:""""]
  Fields = ${AirWatchParserTemplates.airwatch-auth-activity.Fields}[]
  DupFields = ["event_type->auth_type"]

airwatch-auth-activity = {
    Vendor = AirWatch
    Product = AirWatch
    Lms = Splunk
    TimeFormat = "MMMM dd, yyyy HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """Event Timestamp:\s{0,100}({time}\w+\s{0,100}\d\d,\s{0,100}\d\d\d\d\s{0,100}\d\d:\d\d:\d\d)""",
      """\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s{0,100}\[mdmAirwatch""",
      """Event Category:"{1,20}({event_name}[^"]{1,2000})"""",
      """EnrollmentUser:"{1,20}(N\/A|({user}[^"]{1,2000}))"""",
      """Event:"{1,20}({outcome}[^"]{1,2000})"""",
      """Event Data:"{1,20}({additional_info}[^"]{1,2000})"""",
      """DeviceFriendlyName:"{1,20}((N\/A)|(DELETE IN PROGRESS...)|({device_name}[^"]{1,2000}))"""",
      """Reason=({failure_reason}[^"]{1,2000})"""",
    ]
     DupFields = ["device_name->src_host"
}
```