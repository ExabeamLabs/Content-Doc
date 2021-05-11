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
    """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+[\+\-]\d{1,100}:\d{1,100})""",
    """\Wrt=({time}\d{1,100})""",
    """({host}[\w\-.]+)\s{1,100}CEF:""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdvchost=({host}[^\s]+)""",
    """\WflexString1=({sender}.+?)\s{1,100}\w+=""",
    """\WflexString1=(?:[^@]+@)?({external_domain_sender}[^\s]+)\s{1,100}\w+=""",
    """\WflexString2=({recipients}.+?)\s{1,100}\w+=""",
    """\WflexString2=({recipient}[^\s;]+)""",
    """\WflexString2=(?:[^@;\s]+@)?({external_domain_recipient}[^\s;]+)""",
    """\Wmsg=({subject}.+?)\s{1,100}\w+=""",
    """\WeventId=({alert_id}[^\s]+)""",
    """\Wcs1=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\|Trend Micro\|Control Manager\|[^|]+\|[^|]+\|({alert_name}[^|]+)\|""",
    """\|Trend Micro\|Control Manager\|[^|]+\|[^|]+\|[^|]+\|({alert_severity}[^|]+)\|""",
    """\|Trend Micro\|([^|]+\|){2}({alert_type}[^|]+)""",
    """\Wfname=({attachment}.+?)\s{1,100}\w+=""",
    """\Wfname=[^=]+?(\.({file_ext}[^\s;\.\(\)]+))\s{0,100}(\(.*\))?\s{1,100}(\w+=|$)""",
    """\Wsuser=({suser}.+?)\s{1,100}\w+=""",
    """\WfilePath=({file_path}.+?)\s{1,100}\w+=""",
    """\Wdhost=({src_host}[\w\-.]+)""",
    """\Wdst=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wcs5=({action}.+?)\s{1,100}(\w+=|$)""",
    """\WdeviceFacility=({device_facility}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=(({domain}[^\\\s@]+)\\+)?({user}[^\\\s@]+)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_email}[^\\\s@;,]+@[^\\\s@;,]+).*?\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_lastname}[^,\(]+),\s{0,100}({user_firstname}[^,\)\=]+?)(\s{0,100}\([^\)]*\))?\s{1,100}(\w+=|$)""",
    """cn3Label=Security_Threat_Type.*?\Wcn3=({alert_severity}.+?)\s{1,100}(\w+=|$)""",
    """\sfileHash=({md5}\S+)""",
  ]
  DupFields = [ "attachment->file_name" ]
}
```