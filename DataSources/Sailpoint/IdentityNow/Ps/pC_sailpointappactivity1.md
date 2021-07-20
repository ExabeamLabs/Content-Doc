#### Parser Content
```Java
{
Name = sailpoint-app-activity-1
  Conditions = [ """"type": "SSO"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"target":[^\}]{1,2000}?"name":\s{0,100}"(Not Available|({target_user}[^\s",]{1,2000}))""""
  ]
}
```