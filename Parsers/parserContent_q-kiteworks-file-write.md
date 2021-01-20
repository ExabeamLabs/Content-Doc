#### Parser Content
```Java
{
Name = q-kiteworks-file-write
  Product = KiteWorks
  Conditions = [ """Created folder""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}Created) folder ({file_name}.+?)\.\s*(File:|$)""",
    """({accesses}Created) folder "+({file_name}[^"]+)"""",
  ]
}
```