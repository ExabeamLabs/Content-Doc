#### Parser Content
```Java
{
Name = q-kiteworks-file-download-2
  Product = Kiteworks
  Conditions = [ """Downloaded """, """Activity:""" ]
  Fields = ${KiteWorksParserTemplates.q-kiteworks-file-activity.Fields}[
    """\sDownloaded (file|attachment)\s+({file_name}.+?(\.({file_ext}\w+)))\.\s+(Subject|File):""",
    """({accesses}Downloaded)""",
    """with Files:\s*({file_name}[^,]+?(\.({file_ext}\w+))?.*?)\.\s*$""",
  ]
}
```