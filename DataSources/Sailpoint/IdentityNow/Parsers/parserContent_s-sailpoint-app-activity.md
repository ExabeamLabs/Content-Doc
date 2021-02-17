#### Parser Content
```Java
{
Name = s-sailpoint-app-activity
  Conditions = [""""type": "NONE""",""""application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"application":\s*"({app}[^"]+)"""",
    """"info":\s*"((NONE)|({additional_info}[^"]+))""""
  ]
}
```