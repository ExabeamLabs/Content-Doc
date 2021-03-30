#### Parser Content
```Java
{
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
cef-trendmicro-security-alert = {
  Vendor = Trend Micro
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Fields = [
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+(\+|\-)\d\d:\d\d)""",
    """\WeventId=({alert_id}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\Wdvc=({host}.+?)(\s+\w+=|\s*$|\s*")""",
    """\Wdvchost=({host}.+?)(\s+\w+=|\s*$|\s*")""",
    """\Wrt=({time}\w+\s+\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\sshost=({src_host}[^\s]+)""",
    """\sdhost=({dest_host}[^\s]+)""",
    """\Wapp=({app}.+?)(\s+\w+=|\s*$|\s*")""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({src_port}\d+)""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({dest_port}\d+)""",
    """\Wact=({outcome}.+?)(\s+\w+=|\s*$|\s*")""",
    """\Wcn3=({threat_type}.+?)(\s+\w+=|\s*$|\s*")""",
    """\Wrequest="*(|({malware_url}[^"]+?))(\s+\w+=|\s*$|\s*")""",
    """\WdeviceProcessName =({process}({directory}[^=]*?)({process_name}[^\/\\=]+?))(\s+\w+=|\s*$|\s*")""",
  ]

```