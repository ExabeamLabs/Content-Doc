#### Parser Content
```Java
{
Name = n-forwarded-cef-failed-logon-2003
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-failed-logon"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-211005", "failure"]
    Fields = [
      """({event_name}Logon Failure)""",
      """\|McAfee\|[^|]+?\|[^|]+?\|43-21100({event_code}\d{1,100})(0|1)\|""",
      """\srt=({time}\d{1,100})""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """sntdom=({domain}[^\s]+)""",
      """nitroLogon_Type=({logon_type}\d{1,100})""",
      """nitroAppID=({auth_package}[^\s]+)""",
      """suser=({caller_user}.+?)\s{1,100}\w+=""",
      """suser=({user}.+?)\s{1,100}\w+=""",
      """duser=({user}.+?)\s{1,100}\w+=""",
      """src=({src_ip}[a-fA-F:\d.]+)""",
      """nitroSource_Logon_ID=\([^,]+,({logon_id}[^\)]+)""",
      """nitroDestination_Logon_ID=({logon_id}\d{1,100})"""
    ]
    DupFields = ["host->dest_host",
      "event_code->result_code"]
  }
```