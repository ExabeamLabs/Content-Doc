#### Parser Content
```Java
{
Name = q-kiteworks-file-read
  Product = KiteWorks
  Conditions = [ """Viewed file""", """Activity:""", """File: id=""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Viewed) file ({file_name}.+?(\.({file_ext}\w+))?)\.\s+File:\s""",
  ]
}
```