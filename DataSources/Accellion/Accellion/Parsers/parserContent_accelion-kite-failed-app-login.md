#### Parser Content
```Java
{
Name = accelion-kite-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """url_host""", """app_host""", """description""", """user_login_failed""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]{1,2000})"""
    ]

}
```