#### Parser Content
```Java
{
Name = sailpoint-auth
  Conditions = [ """"type": "AUTH"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"info":\s*"(NONE|({additional_info}[^",]+))""""
  ]
}
```