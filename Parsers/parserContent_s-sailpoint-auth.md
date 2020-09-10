#### Parser Content
```Java
{
Name = s-sailpoint-auth
  Conditions = [""""type": "AUTH"""", """"application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"info":\s*"((NONE)|({outcome}[^"]+))""""
  ]
}
```