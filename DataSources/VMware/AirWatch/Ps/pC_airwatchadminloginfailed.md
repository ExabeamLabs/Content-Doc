#### Parser Content
```Java
{
Name = airwatch-admin-login-failed
  DataType = "failed-app-login"
  Conditions = [ """AirWatch""", """Event Timestamp:""", """ConsoleEvent: AdminUserLoginAttemptFailed""" ]
  Fields = ${AirWatchParserTemplates.airwatch-app-activity.Fields}[
    """({outcome}AdminUserLoginAttemptFailed)"""
  ] 

airwatch-app-activity = {
    Vendor = VMware
    Product = AirWatch
    Lms = Splunk
    TimeFormat = "MMMM dd, yyyy HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """Timestamp: ({time}\w+\s\d{1,2},\s\d{4}\s(\d{2}:){2}\d{2})""", 
      """Event Type:\s{0,100}({event_name}[^=]{1,2000}?)\s{0,100}User:""",
      """User:\s{0,100}((({domain}[^\\]{1,2000}?)\\+)?({user}[^:]{1,2000}?))\s{0,100}Event Source:"""
    ]
     DupFields = ["event_name->activity"
}
```