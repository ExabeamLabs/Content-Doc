#### Parser Content
```Java
{
Name = q-kiteworks-file-download-1
  Conditions = [ """Downloaded archive""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Downloaded)""",
    """with Files:\s*({file_name}[^",]+?(\.({file_ext}\w+))?)(,({additional_info}.+?))?\.\s*$""",
    """({accesses}Downloaded) archive "*({file_name}[^"]+?(\.({file_ext}\w+))?)"* from "*({additional_info}[^"]+)""",
  ]
}
```