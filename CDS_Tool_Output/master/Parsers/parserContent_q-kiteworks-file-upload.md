#### Parser Content
```Java
{
Name = q-kiteworks-file-upload
  Product = KiteWorks
  Conditions = [ """Uploaded file""", """Activity:""", """File: id=""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Uploaded) file ({file_name}.+?(\.({file_ext}\w+))?)\.\s*File:""",
    """({accesses}Uploaded) file "+({file_name}[^"]+?(\.({file_ext}\w+))?)"""",
  ]
}
```