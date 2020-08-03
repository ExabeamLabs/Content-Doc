#### Parser Content
```Java
{
Name = accelion-kite-app-setting
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """application_settings_changed""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```