#### Parser Content
```Java
{
Name = accelion-kite-app-activity-6
  DataType = "file-read"
  Conditions = [ """url_host""", """app_host""", """description""", """filehash_generated""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """parent_folder.+hash"{1,20}([^,]+,\s{0,100}"{1,20}name"{1,20}:\s{1,100}"{1,20})({file_name}[^"]+)"{1,20}""",
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}\/:\s({additional_info}.*?)""{0,20}\,\s"{1,20}successful"""
    ]
}
```