#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-2
  Product = Trend Micro Apex One
  Conditions = [ """CEF:""", """|Trend Micro|Apex Central|""" ]
  Fields = ${TrendMicroParserTemplates.cef-trendmicro-security-alert.Fields}[
    """\Wcs1=({alert_name}\S+).+?cs1Label=SLF_PolicyName""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({dest_port}\d+)""",
    """CEF:(?:[^\|]*\|){3}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))\|\w+="""
  ]
}
```