#### Parser Content
```Java
{
Name = accelion-kite-app-activity-3
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """add_user""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}[^"]+)"""
    ]
   DupFields = [ "additional_info->activity" ]
}
```