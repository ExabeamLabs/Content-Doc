#### Parser Content
```Java
{
Name = accelion-kite-app-download-1
  Product = Kiteworks
  DataType = "file-operations"
  Conditions = [ """url_host""", """app_host""", """description""", """download_email""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}attachments.*?,\s{0,100}"{1,20}name"{1,20}:\s{0,100}"{1,20}({file}[^"]{1,2000})"{1,20}([\w\s,":\/.]{1,2000})\}\,\s{0,100}\{.*?,\s{0,100}"{1,20}name"{1,20}:\s{0,100}"{1,20}({file_1}[^"]{1,2000})"{1,20}([\w\s,":\/.]{1,2000})\},\s{0,100}\{.*?,\s{0,100}"{1,20}name"{1,20}:\s{0,100}"{1,20}({file_2}[^"]{1,2000})"{1,20}([\w\s,":\/.()]{1,2000})\},.*?,\s{0,100}"{1,20}name"{1,20}:\s{1,100}"{1,20}({file_3}[^"]{1,2000})""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
}
```