#### Parser Content
```Java
{
Name = xml-sysmon-file-write
  DataType = "file-operations"
  IsHVF = true
  Conditions = [ """<EventID>13</EventID>""", """<Provider Name='Microsoft-Windows-Sysmon'""" ]
  Fields = ${MicrosoftParserTemplates.xml-sysmon-activity.Fields}[
    """<Data Name='TargetObject'>({file_path}(({file_parent}[^<>]+?)[\\\/]+)?({file_name}[^\\\/<>]*?(\.({file_ext}\w+))?))<\/Data>""",
  ]
  DupFields = [ "host->dest_host" ]
}
```