#### Parser Content
```Java
{
Name = s-sailpoint-sso
  Conditions = [""""type": "SSO""",""""application":""", """"id":"""]
  Fields = ${SailPointParserTemplates.s-sailpoint-activity.Fields} [
    """"application":\s*"({app}[^"]+)"""",
    """"info":\s*"((NONE)|({outcome}[^"]+))""""
  ]
}
```