#### Parser Content
```Java
{
Name = q-kiteworks-file-permission-change
  Conditions = [ """Added new permission""", """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """Added new permission ({accesses}.+?) for ({object}.+?) user""",
  ]
}
```