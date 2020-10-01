#### Parser Content
```Java
{
Name = s-sailpoint-pwd
  DataType = "password-change"
  Conditions = [""""type": null""", """"application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"application":\s*"((null)|({app}[^"]+))"""",
    """"info":\s*"((NONE)|({additional_info}[^"]+))""""
  ]
}
```