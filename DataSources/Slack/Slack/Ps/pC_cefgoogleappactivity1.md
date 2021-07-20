#### Parser Content
```Java
{
Name = cef-google-app-activity-1
  Conditions = [ """CEF:""", """|Skyformation|""", """"applicationName":"calendar"""", """"uniqueQualifier":""" ]
  Fields = ${GoogleParserTemplates.cef-google-app-activity.Fields} [
    """({app}calendar)""",
    """"name":"notification_type","value":"({activity}[^"]{1,2000})"""",
    """"name":"recipient_email","value":"({object}[^"]{1,2000})""""
  ]
}
cef-google-app-activity = {
  Vendor = Google
  Product = Google
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"ipAddress":"({src_ip}[\da-fA-F\.:]{1,2000})""",
    """"profileId":"({user_id}\d{1,100})""",
    """"actor":\{[^=]{0,2000}?"email":"({user_email}[^\s@"]{1,2000}@({email_domain}[^\s@"]{1,2000}))"""",
    """"events":\[\{[^\[\]\{\}]{0,2000}"name"\s{0,100}:\s{0,100}"({activity}[^"]{1,2000})"""",
    """"name":"event_id","value":"({additional_info}[^"]{1,2000})"""",
    """"name":"EMAIL_LOG_SEARCH_RECIPIENT","value":"(unknown|({object}[^"]{1,2000}))"""",
    """"name":"EMAIL_LOG_SEARCH_MSG_ID","value":"<?(unknown|({object}[^"]{1,2000}?))>?"""",
    """"name":"app_name","value":"(unknown|({app}[^"]{1,2000}?))\s{0,100}"""",
    """"name":"notification_type","value":"(unknown|({object}[^"]{1,2000}))"""",
    """"name":"user_agent","value":"(unknown|({object}[^"]{1,2000}))"""",
    """"name":"USER_EMAIL","value":"({object}[^"]{1,2000})"""",
    """"name":"calendar_id","value":"({object}[^"]{1,2000})"""",
    """"name":"target_calendar_id","value":"({object}[^"]{1,2000})"""",
    """"name":"group_email","value":"({object}[^"]{1,2000})"""",
    """"name":"status","value":"({object}[^"]{1,2000})"""",
    """"name":"client_id","value":"({object}[^"]{1,2000})"""",
    """"id":\{({additional_info}[^\}]{1,2000})\}"""
  ]

```