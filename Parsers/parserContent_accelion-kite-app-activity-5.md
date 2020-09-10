#### Parser Content
```Java
{
Name = accelion-kite-app-activity-5
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """view_mail""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+subject"+:\s*"+({subject}[^"]+)"+""",
    """To:\s+({recipients}[^"]+)"+""",
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
    DupFields = [ "additional_info->activity" ]
}
```