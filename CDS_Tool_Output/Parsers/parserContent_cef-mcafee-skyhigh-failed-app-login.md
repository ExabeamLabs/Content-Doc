#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-failed-app-login
    DataType = "failed-app-login"
    Conditions = [ """|McAfee (Skyhigh)|Dashboard Audit Logs|""", """User login failed""" ]
    Fields = ${McAfeeParserTemplates.cef-mcafee-skyhigh-activity.Fields}[
      """usrName=Email\s*=\s*"+({user_email}[^"]+)"+,\s*Error:\s*({failure_reason}.+?)(\s+\w+=|\s*$)""",
    ]
  }
```