#### Parser Content
```Java
{
Name = accelion-kite-app-user-delete
  DataType = "app-activity"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_user""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+({additional_info}.*?)""*\,\s"+successful"""
    ]
    DupFields = [ "accesses->activity" ]
}
```