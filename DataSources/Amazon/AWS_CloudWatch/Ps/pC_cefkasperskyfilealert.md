#### Parser Content
```Java
{
Name = cef-kaspersky-file-alert
  DataType = "file-alert"
  Conditions = [ """CEF:""", """|Kaspersky|""", """flexString1=Постоянная защита файлов""" ]
  Fields = ${KasperskyParserTemplates.cef-kaspersky-security-alert.Fields}[
    """\Wmsg=[^=]{0,2000}?Имя объекта:\s{0,100}({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000})?({file_name}[^=\\\/]{0,2000}?(\.({file_ext}\w+))?)?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
cef-kaspersky-security-alert = {
  Vendor = Kaspersky
  Product = Kaspersky AV
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """\Wdvc=({host}[a-fA-F\d.:]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\WdeviceNtDomain=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """CEF:([^\|]{0,2000}\|){5}({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})""",
    """\Wcat=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
   ]

```