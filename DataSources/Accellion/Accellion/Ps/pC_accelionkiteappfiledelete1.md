#### Parser Content
```Java
{
Name = accelion-kite-app-file-delete-1
  DataType = "file-delete"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_folder"""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}folder"{1,20}:.+?:\s"{1,20}({file_name}[^"]{1,2000})?"{0,20}
```