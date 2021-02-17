#### Parser Content
```Java
{
Name = accelion-kite-app-3
  DataType = "file-operations"
  Conditions = [ """url_host""", """app_host""", """description""", """add_file""", """event""" ]
  Fields = ${KiteWorksParserTemplates.accelion-kite-app.Fields}[
    """"+description"+:\s+"+\/:\s({additional_info}[^"]+)""",
    """"*file"*:\s+[^,]+,\s*"*name"*:\s*"*({file_name}[^.].+?(\.({file_ext}\w+)))"+""",
    """({accesses}add_file)"""
    ]
}
```