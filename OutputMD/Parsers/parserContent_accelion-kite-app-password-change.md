#### Parser Content
```Java
{
Name = accelion-kite-app-password-change
  DataType = "password-change"
  Conditions = [ """url_host""", """app_host""", """description""", """update_password""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """\{"+user([^,]+,\s*"+)name"+:\s*"+({target_user}[^"]+)"+""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
}
```