#### Parser Content
```Java
{
Name = s-sailpoint-pwd
  DataType = "password-change"
  Conditions = [""""type": null""", """"application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"application":\s{0,100}"((null)|({app}[^"]+))"""",
    """"info":\s{0,100}"((NONE)|({additional_info}[^"]+))""""
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
    """"hostname":\s{0,100}"((\d)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\d{1,100})|({src_host}[^"]+))"""",
    """"datetime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""",
    """"action":\s{0,100}"({activity}[^"]+)",""",
    """"ipaddr":\s{0,100}"({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
    """"target":\s{0,100}"((\d{1,100})|(unknown|Not Available)|(({user_lastname}[^,"]+),\s{0,100}({user_firstname}[^"]+)))"""",
    """"source":\s{0,100}"((\d{1,100})|(unknown|Not Available)|(({user_lastname}[^,"]+),\s{0,100}({user_firstname}[^"]+)))"""",
    """"target":\s{0,100}"((unknown|Not Available)|({user_fullname}[^\s",]+\s{1,100}[^"]+))"""",
    """"source":\s{0,100}"((unknown|Not Available)|({user_fullname}[^\s",]+\s{1,100}[^"]+))"""",
    """"target":\s{0,100}"((unknown|Not Available)|({user}[^\s,"]+))"""",
    """"source":\s{0,100}"((unknown|Not Available)|({user}[^\s,"]+))"""",
    """"id":\s{0,100}"({fingerprint}[^"]+)",""",
    """"type":\s{0,100}"((NONE)|({event_subtype}[^"]+))""""
  ]

```