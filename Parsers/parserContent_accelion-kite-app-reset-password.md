#### Parser Content
```Java
{
Name = accelion-kite-app-reset-password
  DataType = "account-password-reset"
  Conditions = [ """url_host""", """app_host""", """description""", """reset_password""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+user"+.*?name"+:\s"+({target_user}[^"]+)""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
}
```