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
      """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-21100({event_code}\d{1,100})(0|1)\|""",
      """rt=({time}\d{1,100})""",
      """deviceTranslatedAddress=({host}[a-fA-F:\d.]{1,2000})""",
      """shost=({dest_host}[^\s]{1,2000})""",
      """duser=({account}[\w\-\.]{1,2000}(?:\w+)?\$?)\s{1,100}suser""",
      """suser=({user}[\w\-\.\s]{1,2000}(?:\w+)?\$?)\s{1,100}nitroSource"""
      """sntdom=({domain}.+?)\s{1,100}shost""",
      """nitroSource_Logon_ID=\([^,]{1,2000}
```