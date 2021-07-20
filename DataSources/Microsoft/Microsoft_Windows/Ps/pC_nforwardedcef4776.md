#### Parser Content
```Java
{
Name = n-forwarded-cef-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-4776"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-26304776"]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """\srt=({time}\d{1,100})""",
      """src=({host}[a-fA-F:\d.]{1,2000})""",
      """nitroCommandID=({result_code}.+?)\s{1,100}\w+=""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """sntdom=({domain}[^\s]{1,2000})""",
      """suser=({user}.+?)\s{1,100}\w+=""",
      """suser=({user_emailId}[^\s]{1,2000}@[^\s]{1,2000})\s{1,100}\w+=""",
      """shost=({dest_host}.+?)\s{1,100}\w+="""
    ]
  }
```