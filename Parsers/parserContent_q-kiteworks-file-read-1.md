#### Parser Content
```Java
{
Name = q-kiteworks-file-read-1
  Product = KiteWorks
  Conditions = [ """View file""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """\s({accesses}View) file\s+({file_name}.+?(\.({file_ext}\w+)))(\s+from email.|\.\s+File:)""",
  ]
}
```