#### Parser Content
```Java
{
Name = cef-trendmicro-dlp-alert
  Conditions = [ """|Trend Micro|""", """flexString1=Blocked""", """flexString2=Removable storage""" ]

cef-trendmicro-dlp-alert = {
      Vendor = Trend Micro
      Product = OfficeScan
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Fields = [
        """\Wrt=({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}\w+[\+\-]\d{1,100}:\d{1,100})""",
        """\Wrt=({time}\d{1,100})""",
        """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """\Wdvchost=({host}[^\s]{1,2000})""",
        """\Wcs4=({user}.+?)\s{1,100}(\w+=|$)""",
        """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """\Wshost=({src_host}.+?)\s{1,100}(\w+=|$)""",
        """\Wfname=({file_name}.+?)\s{1,100}(\w+=|$)""",
        """\WfilePath=({file_path}.+?)\s{1,100}(\w+=|$)""",
        """\Wcs5=({alert_name}.+?)\s{1,100}(\w+=|$)""",
        """CEF:([^\|]{0,2000}\|){5}({alert_type}[^\|]{1,2000})""",
        """\WflexString2=({alert_type}.+?)\s{1,100}(\w+=|$)""",
        """\WflexString1=({outcome}.+?)\s{1,100}(\w+=|$)""",
        """\|Trend Micro\|Control Manager\|([^|]{0,2000}\|){3}({alert_severity}[^|]{1,2000})\|""",
        """\Wcs1=({policy_guid}.+?)\s{1,100}(\w+=|$)""",
        """\WdeviceFacility=({additional_info}.+?)\s{1,100}(\w+=|$)""",
        """\Wduser=({target}.+?)\s{1,100}(\w+=|$)""",
        """\Wsuser=({user_lastname}[^,\(]{1,2000}),\s{0,100}({user_firstname}[^,\)\=]{1,2000}?)(\s{0,100}\([^\)]{0,2000}\))?\s{1,100}(\w+=|$)""",
      ]
    }

trendmicro-security-alert = {
  Vendor = Trend Micro
  Product = OfficeScan
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """\Wcat=({threat_category}.+?)\s{0,100}(\w+=|$)""",
    """\Wname=({alert_name}.+?)\s{0,100}(\w+=|$)""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """\WfilePath=({malware_url}.+?)\s{0,100}(\w+=|$)""",
	]
  DupFields = [ "threat_category->alert_type", "host->src_host" 
}
```