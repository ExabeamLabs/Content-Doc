#### Parser Content
```Java
{
Name = accelion-kite-app-login-1
  DataType = "app-login"
  Conditions = [ """url_host""", """app_host""", """description""", """user_logged_in""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}[^"]{1,2000})"""
    ]
}
```