#### Parser Content
```Java
{
Name = n-forwarded-cef-552
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-account-switch"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-21100552"]
    Fields = [
      """({event_name}Logon attempt using explicit credentials)""",
      """\|McAfee\|[^|]+?\|[^|]+?\|43-21100({event_code}\d{1,100})(0|1)\|""",
      """rt=({time}\d{1,100})""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]+)""",
      """shost=({dest_host}[^\s]+)""",
      """duser=({account}[\w\-\.]+(?:\w+)?\$?)\s{1,100}suser""",
      """suser=({user}[\w\-\.\s]+(?:\w+)?\$?)\s{1,100}nitroSource"""
      """sntdom=({domain}.+?)\s{1,100}shost""",
      """nitroSource_Logon_ID=\([^,]+,({logon_id}[^\)]+)"""
    ]
  }
```