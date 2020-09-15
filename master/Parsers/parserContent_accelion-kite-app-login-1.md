#### Parser Content
```Java
{
Name = accelion-kite-app-login-1
  DataType = "app-login"
  Conditions = [ """url_host""", """app_host""", """description""", """user_logged_in""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}[^"]+)"""
    ]
}
```