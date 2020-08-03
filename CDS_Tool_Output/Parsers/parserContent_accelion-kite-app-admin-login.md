#### Parser Content
```Java
{
Name = accelion-kite-app-admin-login
  DataType = "app-login"
  Conditions = [ """url_host""", """app_host""", """description""", """admin_logged_in""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
}
```