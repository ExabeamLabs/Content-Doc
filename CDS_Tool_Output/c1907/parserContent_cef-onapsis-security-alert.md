#### Parser Content
```Java
{
Name = cef-onapsis-security-alert
  DataType = "alert"
  Conditions = [ """CEF:""", """|Onapsis|OSP|""", """OnapsisOSPPolicy=""" ]
  Fields = ${OnapsisParserTemplates.cef-onapsis-activity.Fields}[
    """\Wcat=(None|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wsev=({alert_severity}\d+)""",
    """\Wmsg=(None|({alert_name}.+?))(\s+\w+=|\s*$)""",
  ]
}
```