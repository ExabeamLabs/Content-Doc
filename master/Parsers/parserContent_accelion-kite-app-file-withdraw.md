#### Parser Content
```Java
{
Name = accelion-kite-app-file-withdraw
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """file_withdrawn""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```