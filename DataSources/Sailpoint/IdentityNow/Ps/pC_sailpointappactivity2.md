#### Parser Content
```Java
{
Name = sailpoint-app-activity-2
  Conditions = [ """"type": "USER_MANAGEMENT"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"info":\s{0,100}"(NONE|({additional_info}[^",]{1,2000}))""""
  ]
}
```