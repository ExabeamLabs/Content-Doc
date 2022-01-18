#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert-8
  Product = Trend Micro
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
  Conditions = [ """CEF:""", """WordPress Social Warfare Unauthenticated Settings Update Vulnerability (CVE-2019-9978)""" ]

cef-trendmicro-security-alert = {
  Vendor = Trend Micro
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss zZ"
  Fields = [
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|(Unknown|({alert_severity}[^\|]{1,2000}))""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)""",
    """\WeventId=({alert_id}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\Wdvc=({host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wdvchost=({host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """rt=({time}\w+\s{1,100}\d\d \d\d\d\d \d\d:\d\d:\d\d \S+)""",
    """\sshost=(({src_host}[\w\-.]{1,2000})|({additional_info}[^@]{1,2000}@[^\s]{1,2000}))\s{1,100}\w+=""",
    """\sdhost=({dest_host}[\w\-.]{1,2000})\s{1,100}\w+=""",
    """\Wapp=({app}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wdst=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdpt=({src_port}\d{1,100})""",
    """\Wsrc=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wspt=({dest_port}\d{1,100})""",
    """\Wact=(Unknown|({outcome}[^=]{1,2000}?))(?:\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wcn3=({threat_type}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\Wrequest="{0,20}(|({malware_url}[^"]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$|\s{0,100}"|”\]{1,2000}\s{1,100}\w+=)""",
    """\WdeviceProcessName =({process}({directory}[^=]{0,2000}?)({process_name}[^\/\\=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$|\s{0,100}")""",
    """\sduser=((\d{1,3}\.){3}\d{1,3}|({user_email}[^@\s]{1,2000}@[^\.\s]{1,2000}\.[^\s]{1,2000}?)|({user}[^\s]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfilePath=({malware_url}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sfileHash=({md5}\w+)(\s{1,100}\w+=|\s{0,100}$)"""
  
}
```