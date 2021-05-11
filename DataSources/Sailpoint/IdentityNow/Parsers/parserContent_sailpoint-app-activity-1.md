#### Parser Content
```Java
{
Name = sailpoint-app-activity-1
  Conditions = [ """"type": "SSO"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"target":[^\}]+?"name":\s{0,100}"(Not Available|({target_user}[^\s",]+))""""
  ]
}
```