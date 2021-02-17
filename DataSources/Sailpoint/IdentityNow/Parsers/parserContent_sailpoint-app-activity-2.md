#### Parser Content
```Java
{
Name = sailpoint-app-activity-2
  Conditions = [ """"type": "USER_MANAGEMENT"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"info":\s*"(NONE|({additional_info}[^",]+))""""
  ]
}
```