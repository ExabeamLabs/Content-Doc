#### Parser Content
```Java
{
Name = accelion-kite-app-file-delete
  DataType = "file-delete"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_folder_permanent""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+folder"+:.+?:\s"+({file_name}[^"]+)?"*,\s+"+path"+:\s"+({path}[^"]+)?"*\,""",
    """"+description"+:\s+"+\/:\s({additional_info}[^"]+)"""
  ]
}
```