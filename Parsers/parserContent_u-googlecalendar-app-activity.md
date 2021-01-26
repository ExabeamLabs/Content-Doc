#### Parser Content
```Java
{
Name = u-googlecalendar-app-activity
  Vendor = Google
  Product = Google Calendar
  Lms = Sumo
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"applicationName":""", """"calendar"""", """"uniqueQualifier":""",  """"event_change"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s*:\s*"({user_id}\d+)""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user_email}({user}[^@"]+)@[^"]+)"""",
    """"type"\s*:\s*"event_change",\s*"name"\s*:\s*"({activity}[^"]+)"""",
    """"type"\s*:\s*"event_change".*?"name"\s*:\s*"event_id",\s*"value"\s*:\s*"({additional_info}[^"]+)"""",
    """"type"\s*:\s*"event_change".*?"name"\s*:\s*"event_title",\s*"value"\s*:\s*"({object}[^"]+)"""",
  ]
}
```