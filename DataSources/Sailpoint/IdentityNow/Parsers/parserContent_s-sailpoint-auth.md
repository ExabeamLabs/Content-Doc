#### Parser Content
```Java
{
Name = s-sailpoint-auth
  Conditions = [""""type": "AUTH"""", """"application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"info":\s*"((NONE)|({outcome}[^"]+))""""
  ]
}
s-sailpoint-activity = {
  Vendor = Sailpoint
  Product = IdentityNow
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"hostname":\s*"((\d)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\d+)|({src_host}[^"]+))"""",
    """"datetime":\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """"action":\s*"({activity}[^"]+)",""",
    """"ipaddr":\s*"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"target":\s*"((\d+)|(unknown|Not Available)|(({user_lastname}[^,"]+),\s*({user_firstname}[^"]+)))"""",
    """"source":\s*"((\d+)|(unknown|Not Available)|(({user_lastname}[^,"]+),\s*({user_firstname}[^"]+)))"""",
    """"target":\s*"((unknown|Not Available)|({user_fullname}[^\s",]+\s+[^"]+))"""",
    """"source":\s*"((unknown|Not Available)|({user_fullname}[^\s",]+\s+[^"]+))"""",
    """"target":\s*"((unknown|Not Available)|({user}[^\s,"]+))"""",
    """"source":\s*"((unknown|Not Available)|({user}[^\s,"]+))"""",
    """"id":\s*"({fingerprint}[^"]+)",""",
    """"type":\s*"((NONE)|({event_subtype}[^"]+))""""
  ]

```