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
    """({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdvchost=({host}[^\s]{1,2000})""",
    """\WflexString1=({sender}.+?)\s{1,100}\w+=""",
    """\WflexString1=(?:[^@]{1,2000}@)?({external_domain_sender}[^\s]{1,2000})\s{1,100}\w+=""",
    """\WflexString2=({recipients}.+?)\s{1,100}\w+=""",
    """\WflexString2=({recipient}[^\s;]{1,2000})""",
    """\WflexString2=(?:[^@;\s]{1,2000}@)?({external_domain_recipient}[^\s;]{1,2000})""",
    """\Wmsg=({subject}.+?)\s{1,100}\w+=""",
    """\WeventId=({alert_id}[^\s]{1,2000})""",
    """\Wcs1=({alert_name}.+?)\s{1,100}(\w+=|$)""",
    """\|Trend Micro\|Control Manager\|[^|]{1,2000}\|[^|]{1,2000}\|({alert_name}[^|]{1,2000})\|""",
    """\|Trend Micro\|Control Manager\|[^|]{1,2000}\|[^|]{1,2000}\|[^|]{1,2000}\|({alert_severity}[^|]{1,2000})\|""",
    """\|Trend Micro\|([^|]{1,2000}\|){2}({alert_type}[^|]{1,2000})""",
    """\Wfname=({attachment}.+?)\s{1,100}\w+=""",
    """\Wfname=[^=]{1,2000}?(\.({file_ext}[^\s;\.\(\)]{1,2000}))\s{0,100}(\(.*\))?\s{1,100}(\w+=|$)""",
    """\Wsuser=({suser}.+?)\s{1,100}\w+=""",
    """\WfilePath=({file_path}.+?)\s{1,100}\w+=""",
    """\Wdhost=({src_host}[\w\-.]{1,2000})""",
    """\Wdst=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wcs5=({action}.+?)\s{1,100}(\w+=|$)""",
    """\WdeviceFacility=({device_facility}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=(({domain}[^\\\s@]{1,2000})\\+)?({user}[^\\\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wduser=({user_email}[^\\\s@;,]{1,2000}@[^\\\s@;,]{1,2000}).*?\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_lastname}[^,\(]{1,2000}),\s{0,100}({user_firstname}[^,\)\=]{1,2000}?)(\s{0,100}\([^\)]{0,2000}\))?\s{1,100}(\w+=|$)""",
    """cn3Label=Security_Threat_Type.*?\Wcn3=({alert_severity}.+?)\s{1,100}(\w+=|$)""",
    """\sfileHash=({md5}\S+)""",
  ]
  DupFields = [ "attachment->file_name" ]


}
```