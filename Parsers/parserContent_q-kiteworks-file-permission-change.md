#### Parser Content
```Java
{
Name = q-kiteworks-file-permission-change
  Product = KiteWorks
  Conditions = [ """Added new permission""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """Added new permission ({accesses}.+?) for ({object}.+?) user""",
  ]
}
```