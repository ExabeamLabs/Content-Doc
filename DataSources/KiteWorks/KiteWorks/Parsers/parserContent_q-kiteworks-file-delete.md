#### Parser Content
```Java
{
Name = q-kiteworks-file-delete
  Product = KiteWorks
  Conditions = [ """Deleted folder""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Deleted) folder "+({file_name}[^"]+)"""",
  ]
}
```