#### Parser Content
```Java
{
Name = s-sailpoint-app-activity
  Conditions = [""""type": "NONE""",""""application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"application":\s{0,100}"({app}[^"]{1,2000})"""",
    """"info":\s{0,100}"((NONE)|({additional_info}[^"]{1,2000}))""""
  ]
}
s-sailpoint-activity = {
  Vendor = Sailpoint
  Product = IdentityNow
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"hostname":\s{0,100}"((\d)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\d{1,100})|({src_host}[^"]{1,2000}))"""",
    """"datetime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """"action":\s{0,100}"({activity}[^"]{1,2000})",""",
    """"ipaddr":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"target":\s{0,100}"((\d{1,100})|(unknown|Not Available)|(({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})))"""",
    """"source":\s{0,100}"((\d{1,100})|(unknown|Not Available)|(({user_lastname}[^,"]{1,2000}),\s{0,100}({user_firstname}[^"]{1,2000})))"""",
    """"target":\s{0,100}"((unknown|Not Available)|({user_fullname}[^\s",]{1,2000}\s{1,100}[^"]{1,2000}))"""",
    """"source":\s{0,100}"((unknown|Not Available)|({user_fullname}[^\s",]{1,2000}\s{1,100}[^"]{1,2000}))"""",
    """"target":\s{0,100}"((unknown|Not Available)|({user}[^\s,"]{1,2000}))"""",
    """"source":\s{0,100}"((unknown|Not Available)|({user}[^\s,"]{1,2000}))"""",
    """"id":\s{0,100}"({fingerprint}[^"]{1,2000})",""",
    """"type":\s{0,100}"((NONE)|({event_subtype}[^"]{1,2000}))""""
  ]

```