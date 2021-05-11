#### Parser Content
```Java
{
Name = accelion-kite-app-3
  DataType = "file-operations"
  Conditions = [ """url_host""", """app_host""", """description""", """add_file""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"{1,20}description"{1,20}:\s{1,100}"{1,20}\/:\s({additional_info}[^"]+)""",
    """"{0,20}file"{0,20}:\s{1,100}[^,]+,\s{0,100}"{0,20}name"{0,20}:\s{0,100}"{0,20}({file_name}[^.].+?(\.({file_ext}\w+)))"{1,20}""",
    """({accesses}add_file)"""
    ]
}
```