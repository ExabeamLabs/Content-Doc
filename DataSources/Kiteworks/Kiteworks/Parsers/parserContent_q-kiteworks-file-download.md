#### Parser Content
```Java
{
Name = q-kiteworks-file-download
  Product = Kiteworks
  Conditions = [ """Downloaded file""", """Activity:""", """File: id=""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Downloaded) file ({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}[^\.]+))?))\.\s+File:\s""",
  ]
}
```