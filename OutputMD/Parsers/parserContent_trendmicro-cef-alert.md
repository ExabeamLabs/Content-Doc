#### Parser Content
```Java
{
Name = trendmicro-cef-alert
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|Trend Micro|Control Manager|""" ]
  Fields = [
    """\Wrt=({time}\w+\s+\d+\s+\d+\s+\d+:\d+:\d+\s+\w+[\+\-]\d+:\d+)""",
    """\Wrt=({time}\d+)""",
    """({host}[\w\-.]+)\s+CEF:""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdvchost=({host}[^\s]+)""",
    """\WflexString1=({sender}.+?)\s+\w+=""",
    """\WflexString1=(?:[^@]+@)?({external_domain_sender}[^\s]+)\s+\w+=""",
    """\WflexString2=({recipients}.+?)\s+\w+=""",
    """\WflexString2=({recipient}[^\s;]+)""",
    """\WflexString2=(?:[^@;\s]+@)?({external_domain_recipient}[^\s;]+)""",
    """\Wmsg=({subject}.+?)\s+\w+=""",
    """\WeventId=({alert_id}[^\s]+)""",
    """\Wcs1=({alert_name}.+?)\s+(\w+=|$)""",
    """\|Trend Micro\|Control Manager\|[^|]+\|[^|]+\|({alert_name}[^|]+)\|""",
    """\|Trend Micro\|Control Manager\|[^|]+\|[^|]+\|[^|]+\|({alert_severity}[^|]+)\|""",
    """\|Trend Micro\|([^|]+\|){2}({alert_type}[^|]+)""",
    """\Wfname=({attachment}.+?)\s+\w+=""",
    """\Wfname=[^=]+?(\.({file_ext}[^\s;\.\(\)]+))\s*(\(.*\))?\s+(\w+=|$)""",
    """\Wsuser=({suser}.+?)\s+\w+=""",
    """\WfilePath=({file_path}.+?)\s+\w+=""",
    """\Wdhost=({src_host}[\w\-.]+)""",
    """\Wdst=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs5=({action}.+?)\s+(\w+=|$)""",
    """\WdeviceFacility=({device_facility}.+?)\s+(\w+=|$)""",
    """\Wduser=(({domain}[^\\\s@]+)\\+)?({user}[^\\\s@]+)\s+(\w+=|$)""",
    """\Wduser=({user_email}[^\\\s@;,]+@[^\\\s@;,]+).*?\s+(\w+=|$)""",
    """\Wsuser=({user_lastname}[^,\(]+),\s*({user_firstname}[^,\)\=]+?)(\s*\([^\)]*\))?\s+(\w+=|$)""",
    """cn3Label=Security_Threat_Type.*?\Wcn3=({alert_severity}.+?)\s+(\w+=|$)""",
    """\sfileHash=({md5}\S+)""",
  ]
  DupFields = [ "attachment->file_name" ]
}
```