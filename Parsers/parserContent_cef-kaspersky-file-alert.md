#### Parser Content
```Java
{
Name = cef-kaspersky-file-alert
  DataType = "file-alert"
  Conditions = [ """CEF:""", """|Kaspersky|""", """flexString1=Постоянная защита файлов""" ]
  Fields = ${KasperskyParserTemplates.cef-kaspersky-security-alert.Fields}[
    """\Wmsg=[^=]*?Имя объекта:\s*({file_path}({file_parent}[^=]*?[\\\/]+)?({file_name}[^=\\\/]*?(\.({file_ext}\w+))?)?)(\s+\w+=|\s*$)""",
  ]
}
```