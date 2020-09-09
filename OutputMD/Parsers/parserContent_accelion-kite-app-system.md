#### Parser Content
```Java
{
Name = accelion-kite-app-system
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """System""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
   DupFields = [ "additional_info->activity" ]
}
```