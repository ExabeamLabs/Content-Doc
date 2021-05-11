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
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s{0,100}:\s{0,100}"({user_id}\d{1,100})""",
    """"actor"\s{0,100}:\s{0,100}\{.*?"email"\s{0,100}:\s{0,100}"({user_email}({user}[^@"]+)@[^"]+)"""",
    """"type"\s{0,100}:\s{0,100}"event_change",\s{0,100}"name"\s{0,100}:\s{0,100}"({activity}[^"]+)"""",
    """"type"\s{0,100}:\s{0,100}"event_change".*?"name"\s{0,100}:\s{0,100}"event_id",\s{0,100}"value"\s{0,100}:\s{0,100}"({additional_info}[^"]+)"""",
    """"type"\s{0,100}:\s{0,100}"event_change".*?"name"\s{0,100}:\s{0,100}"event_title",\s{0,100}"value"\s{0,100}:\s{0,100}"({object}[^"]+)"""",
  ]
}
```