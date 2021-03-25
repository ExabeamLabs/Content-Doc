#### Parser Content
```Java
{
Name = q-kiteworks-file-read
  Product = Kiteworks
  Conditions = [ """Viewed file""", """Activity:""", """File: id=""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """({accesses}View(ed)?) file (({file_name}[^,]+\.({file_ext}[^\s,\.]+)))[^:]+?File:"""
  ]
}
```