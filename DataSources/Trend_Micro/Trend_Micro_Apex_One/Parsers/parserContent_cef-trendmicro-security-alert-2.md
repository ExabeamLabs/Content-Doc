#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-2
  Product = Trend Micro Apex One
  Conditions = [ """CEF:""", """|Trend Micro|Apex Central|""" ]
  Fields = ${TrendMicroParserTemplates.cef-trendmicro-security-alert.Fields}[
    """\Wcs1=(?:N\/A|({alert_name}[^=]+?))\s{1,100}\w+=""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))""",
    """cn2=({cn2}[^\s"]+)""",
  ]
  DupFields = [ "outcome->action", "alert_name->alert_type" ]
}
cef-trendmicro-security-alert = {
  Vendor = Trend Micro
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Fields = [
    """CEF:([^\|]*\|){4}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|(Unknown|({alert_severity}[^\|]+))""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\Wdvc=({host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wdvchost=({host}[^=]+?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """rt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\sshost=(({src_host}[\w\-.]+)|({additional_info}[^@]+@[^\s]+))\s{1,100}\w+=""",
    """\sdhost=({dest_host}[\w\-.]+)\s{1,100}\w+=""",
    """\Wapp=({app}[^=]+?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wdst=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdpt=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wspt=({dest_port}\d{1,100})""",
    """\Wact=(Unknown|({outcome}[^=]+?))(?:\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wcn3=({threat_type}[^=]+?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wrequest="{0,20}(|({malware_url}[^"]+?))(\s{1,100}\w+=|\s{0,100}$|\s{0,100}"|”\]+\s{1,100}\w+=)""",
    """\WdeviceProcessName=({process}({directory}[^=]*?)({process_name}[^\/\\=]+?))(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\sduser=((\d{1,3}\.){3}\d{1,3}|({user_email}[^@\s]+@[^\.\s]+\.[^\s]+?)|({user}[^\s]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfilePath=({malware_url}[^=]+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfileHash=({md5}\w+)(\s{1,100}\w+=|\s{0,100}$)"""
  ]

```