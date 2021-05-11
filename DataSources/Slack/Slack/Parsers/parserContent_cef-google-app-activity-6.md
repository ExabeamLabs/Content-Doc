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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress":"({src_ip}[\da-fA-F\.:]+)""",
    """"profileId":"({user_id}\d{1,100})""",
    """"actor":\{[^=]*?"email":"({user_email}[^\s@"]+@({email_domain}[^\s@"]+))"""",
    """"events":\[\{[^\[\]\{\}]*"name"\s{0,100}:\s{0,100}"({activity}[^"]+)"""",
    """"name":"event_id","value":"({additional_info}[^"]+)"""",
    """"name":"EMAIL_LOG_SEARCH_RECIPIENT","value":"(unknown|({object}[^"]+))"""",
    """"name":"EMAIL_LOG_SEARCH_MSG_ID","value":"<?(unknown|({object}[^"]+?))>?"""",
    """"name":"app_name","value":"(unknown|({app}[^"]+?))\s{0,100}"""",
    """"name":"notification_type","value":"(unknown|({object}[^"]+))"""",
    """"name":"user_agent","value":"(unknown|({object}[^"]+))"""",
    """"name":"USER_EMAIL","value":"({object}[^"]+)"""",
    """"name":"calendar_id","value":"({object}[^"]+)"""",
    """"name":"target_calendar_id","value":"({object}[^"]+)"""",
    """"name":"group_email","value":"({object}[^"]+)"""",
    """"name":"status","value":"({object}[^"]+)"""",
    """"name":"client_id","value":"({object}[^"]+)"""",
    """"id":\{({additional_info}[^\}]+)\}"""
  ]

```