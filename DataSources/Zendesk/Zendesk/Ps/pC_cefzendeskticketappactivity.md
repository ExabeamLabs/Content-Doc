#### Parser Content
```Java
{
Name = cef-zendesk-ticket-app-activity
  Conditions = [ """CEF:""", """"zendesk-event": "TRUE"""", """"detail-type": """", """"ticket_event":""" ]
  Fields = ${ZendeskParserTemplates.cef-zendesk-app-activity.Fields} [
    """"ticket":\s{0,100}\{({additional_info}[^\}]{1,2000})\}""",
  ]

cef-zendesk-app-activity = {
  Vendor = Zendesk
  Product = Zendesk
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """time":\s{0,100}"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""",
    """"date":({time}\d{1,100})""",
    """({app}zendesk)""",
    """"actor_id":\s{0,100}({user_id}\d{1,2000})""",
    """"detail-type": "({event_name}[^"]{1,2000})"""",
    """"detail":[^=]{1,2000}?"type": "({activity}[^"]{1,2000})"""",
    """"resources": \[?"Support ({object}[^"]{1,2000})"""",
    """"region": "({region}[^"]{1,2000})""""
  ]
 
}
```