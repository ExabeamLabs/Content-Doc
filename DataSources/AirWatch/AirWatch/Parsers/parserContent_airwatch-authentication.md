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
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """Event Timestamp:\s*({time}\w+\s*\d\d,\s*\d\d\d\d\s*\d\d:\d\d:\d\d)""",
      """\s({host}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s*\[mdmAirwatch""",
      """Event Category:"+({event_name}[^"]+)"""",
      """EnrollmentUser:"+(N\/A|({user}[^"]+))"""",
      """Event:"+({outcome}[^"]+)"""",
      """Event Data:"+({additional_info}[^"]+)"""",
      """DeviceFriendlyName:"+((N\/A)|(DELETE IN PROGRESS...)|({device_name}[^"]+))"""",
      """Reason=({failure_reason}[^"]+)"""",
    ]

```