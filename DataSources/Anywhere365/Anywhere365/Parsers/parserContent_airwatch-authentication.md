#### Parser Content
```Java
{
Name = airwatch-authentication
  DataType = "authentication-successful" 
  Conditions = [ """AirWatch""", """Event Category:"Authentication"""", """Event:""""]
  Fields = ${AirWatchParserTemplates.airwatch-auth-activity.Fields}[]
  DupFields = ["event_type->auth_type"]
}
airwatch-auth-activity = {
    Vendor = AirWatch
    Product = AirWatch
    Lms = Splunk
    TimeFormat = "MMMM dd, yyyy HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """Event Timestamp:\s{0,100}({time}\w+\s{0,100}\d\d,\s{0,100}\d\d\d\d\s{0,100}\d\d:\d\d:\d\d)""",
      """\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s{0,100}\[mdmAirwatch""",
      """Event Category:"{1,20}({event_name}[^"]+)"""",
      """EnrollmentUser:"{1,20}(N\/A|({user}[^"]+))"""",
      """Event:"{1,20}({outcome}[^"]+)"""",
      """Event Data:"{1,20}({additional_info}[^"]+)"""",
      """DeviceFriendlyName:"{1,20}((N\/A)|(DELETE IN PROGRESS...)|({device_name}[^"]+))"""",
      """Reason=({failure_reason}[^"]+)"""",
    ]

```