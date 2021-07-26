#### Parser Content
```Java
{
Name = sailpoint-password-change
  DataType = "password-change"
  Conditions = [ """"type": "PASSWORD_ACTIVITY"""", """"stack": """", """"attributes":""" ]
  Fields = ${SailPointParserTemplates.sailpoint-activity-1.Fields} [
     """"accountName":\s{0,100}"({user_ou}\w+=[^"]{1,2000})"""",
     """"target":[^\}]{1,2000}?"name":\s{0,100}"(Not Available|({target_user}[^\s",]{1,2000}))""""
  ]
}
```