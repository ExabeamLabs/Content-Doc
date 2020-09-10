#### Parser Content
```Java
{
Name = accelion-kite-app-file-delete-1
  DataType = "file-delete"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_folder"""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+folder"+:.+?:\s"+({file_name}[^"]+)?"*,\s+"+path"+:\s"+({path}[^"]+)?"*\,""",
    """"+description"+:\s+"+\/:\s({additional_info}[^"]+)"""
  ]
}
```