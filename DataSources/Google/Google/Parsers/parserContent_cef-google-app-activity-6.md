#### Parser Content
```Java
{
Name = cef-google-app-activity-6
  Conditions = [ """CEF:""", """|Skyformation|""", """"applicationName":"token"""", """"uniqueQualifier":""", """flexString1=activity""", """flexString1Label=application-action""" ]
  Fields = ${GoogleParserTemplates.cef-google-app-activity.Fields} [
    """"events":.*?"name":"method_name"[^\}]+?"value":"({activity}[^"]+?)""""
  ]
}
cef-google-app-activity = {
  Vendor = Google
  Product = Google
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}[\w\-.]+)\s+Skyformation""",
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId"\s*:\s*"({user_id}\d+)""",
    """"actor"\s*:\s*\{.*?"email"\s*:\s*"({user_email}[^\s@"]+@[^\s@"]+)"""",
    """"events"\s*:\[\{[^\[\]\{\}]*"name"\s*:\s*"({activity}[^"]+)"""",
    """"name"\s*:\s*"event_id",\s*"value"\s*:\s*"({additional_info}[^"]+)"""",
    """"name"\s*:\s*"EMAIL_LOG_SEARCH_RECIPIENT",\s*"value"\s*:\s*"(unknown|({object}[^"]+))"""",
    """"name"\s*:\s*"EMAIL_LOG_SEARCH_MSG_ID",\s*"value"\s*:\s*"<?(unknown|({object}[^"]+?))>?"""",
    """"name"\s*:\s*"app_name",\s*"value"\s*:\s*"(unknown|({app}[^"]+?))\s*"""",
    """"name"\s*:\s*"notification_type",\s*"value"\s*:\s*"(unknown|({object}[^"]+))"""",
    """"name"\s*:\s*"user_agent",\s*"value"\s*:\s*"(unknown|({object}[^"]+))"""",
    """"name"\s*:\s*"USER_EMAIL",\s*"value"\s*:\s*"({object}[^"]+)"""",
    """"name"\s*:\s*"calendar_id",\s*"value"\s*:\s*"({object}[^"]+)"""",
    """"name"\s*:\s*"target_calendar_id",\s*"value"\s*:\s*"({object}[^"]+)"""",
    """"name"\s*:\s*"group_email",\s*"value"\s*:\s*"({object}[^"]+)"""",
    """"name"\s*:\s*"status",\s*"value"\s*:\s*"({object}[^"]+)"""",
  ]

```