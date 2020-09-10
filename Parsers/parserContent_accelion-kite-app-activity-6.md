#### Parser Content
```Java
{
Name = accelion-kite-app-activity-6
  DataType = "file-read"
  Conditions = [ """url_host""", """app_host""", """description""", """filehash_generated""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """parent_folder.+hash"+([^,]+,\s*"+name"+:\s+"+)({file_name}[^"]+)"+""",
    """"+description"+:\s+"+\/:\s({additional_info}.*?)""*\,\s"+successful"""
    ]
}
```