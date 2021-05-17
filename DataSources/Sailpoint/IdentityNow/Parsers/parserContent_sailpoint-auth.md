#### Parser Content
```Java
{
Name = sailpoint-auth
  Conditions = [ """"type": "AUTH"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"info":\s{0,100}"(NONE|({additional_info}[^",]{1,2000}))""""
  ]
}
```