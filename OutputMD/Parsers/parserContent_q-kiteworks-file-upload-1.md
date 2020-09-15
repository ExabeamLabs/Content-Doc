#### Parser Content
```Java
{
Name = q-kiteworks-file-upload-1
  Product = Kiteworks
  Conditions = [ """Uploaded file""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """\s({accesses}Uploaded) file\s+({file_name}.+?(\.({file_ext}\w+)))\.\s+File:""",
  ]
}
```