#### Parser Content
```Java
{
Name = mcafee-dlp-mem-dev
  DataType = "usb-activity"
  Conditions = [ """RulesToDisplay=""", """Portable and Memory Devices""", """ViolationUTCTime=""", """Destination=""", """Username=""", """ViolationTimezone=""", """ViolationLocalTime=""" ]

  Fields = ${McAfeeParserTemplates.mcafee-dlp-activity.Fields} [
    """,\sDestination="*({device_type}[^"]+)"*,\s"""
  ]
}
mcafee-dlp-activity = {
      Vendor = McAfee
      Product = McAfee DLP
      Lms = Splunk
      TimeFormat = "YYYY-MM-dd HH:mm:ss"
      Fields = [
        """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
        """,\sViolationUTCTime="*({time}\d{4}\-\d{2}\-\d{2}\s\d{2}:\d{2}:\d{2})""",
        """,\sRulesToDisplay="*({alert_name}[^"]+)"*,\s""",
        """,\sName="*({src_host}[^"]+)"*,\s""",
        """,\sUsername="*({user}[^"]+)"*,\s""",
        """,\sFilePath="*({file_path}.+?)"*,\s""",
        """,\sFileName="*({file_name}.+?)"*,\s""",
        """,\sFileSize="*({bytes}\d+)"*"""
        ]

```