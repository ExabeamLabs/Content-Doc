#### Parser Content
```Java
{
Name = accelion-kite-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """url_host""", """app_host""", """description""", """user_login_failed""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}[^"]+)"""
    ]

}
```