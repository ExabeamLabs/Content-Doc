#### Parser Content
```Java
{
Name = sailpoint-password-change
  DataType = "password-change"
  Conditions = [ """"type": "PASSWORD_ACTIVITY"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"accountName":\s*"({user_ou}\w+=[^"]+)"""",
     """"target":[^\}]+?"name":\s*"(Not Available|({target_user}[^\s",]+))""""
  ]
}
```