#### Parser Content
```Java
{
Name = s-sailpoint-launch
  Conditions = [""""type": "LAUNCH""", """"application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"application":\s*"({app}[^"]+)"""",
    """"info":\s*"((NONE)|({additional_info}[^"]+))""""
  ]
}
```