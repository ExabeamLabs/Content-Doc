#### Parser Content
```Java
{
Name = accelion-kite-app-activity-6
  DataType = "file-read"
  Conditions = [ """url_host""", """app_host""", """description""", """filehash_generated""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """parent_folder.+hash"{1,20}([^,]{1,2000}
```