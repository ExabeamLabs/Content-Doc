#### Parser Content
```Java
{
Name = mcafee-dlp-rem-stor-2
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay="Removable Storage""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="{0,20}({device_type}[^"]{1,2000})"{0,20}
mcafee-dlp-activity = {
      Vendor = McAfee
      Product = McAfee DLP
      Lms = Splunk
      TimeFormat = "YYYY-MM-dd HH:mm:ss"
      Fields = [
        """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
        """,\sViolationUTCTime="{0,20}({time}\d{4}\-\d{2}\-\d{2}\s\d{2}:\d{2}:\d{2})""",
        """,\sRulesToDisplay="{0,20}({alert_name}[^"]{1,2000})"{0,20},\s""",
        """,\sName="{0,20}({src_host}[^"]{1,2000})"{0,20},\s""",
        """,\sUsername="{0,20}({user}[^"]{1,2000})"{0,20},\s""",
        """,\sFilePath="{0,20}({file_path}.+?)"{0,20},\s""",
        """,\sFileName="{0,20}({file_name}.+?)"{0,20},\s""",
        """,\sFileSize="{0,20}({bytes}\d{1,100})"{0,20}"""
        ]

```