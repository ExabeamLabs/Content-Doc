#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert
  Lms = ArcSight
  Conditions = [ """|Trend Micro|Deep Security Manager|""","cat=" ]
}

${TrendMicroParserTemplates.cef-trendmicro-security-alert}{
  Name = cef-trendmicro-security-alert-2
  Product = Trend Micro Apex One
  Conditions = [ """CEF:""", """|Trend Micro|Apex Central|""" ]
  Fields = ${TrendMicroParserTemplates.cef-trendmicro-security-alert.Fields}[
    """\Wcs1Label=SLF_PolicyName.*?\Wcs1=({alert_name}.+?)(\s+\w+=|\s*$|\s*")""",
    """\Wcs1=({alert_name}\S+).+?cs1Label=SLF_PolicyName""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({dest_port}\d+)""",
  ]
}
```