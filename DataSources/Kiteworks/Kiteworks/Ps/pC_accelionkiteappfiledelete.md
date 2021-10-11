#### Parser Content
```Java
{
Name = accelion-kite-app-file-delete
  Product = Kiteworks
  DataType = "file-delete"
  Conditions = [ """url_host""", """app_host""", """description""", """delete_folder_permanent""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}folder"{1,20}:.+?:\s"{1,20}({file_name}[^"]{1,2000})?"{0,20},\s{1,100}"{1,20}path"{1,20}:\s"{1,20}({path}[^"]{1,2000})?"{0,20}\,""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}\/:\s({additional_info}[^"]{1,2000})"""
  ]
}
```