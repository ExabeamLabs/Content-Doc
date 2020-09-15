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
      """\|McAfee\|.+?\|43-2630({event_code}\d+)(0|1)\|""",
      """\srt=({time}\d+)""",
      """src=({host}[a-fA-F:\d.]+)""",
      """nitroCommandID=({result_code}.+?)\s+\w+=""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """sntdom=({domain}[^\s]+)""",
      """suser=({user}.+?)\s+\w+=""",
      """suser=({user_emailId}[^\s]+@[^\s]+)\s+\w+=""",
      """shost=({dest_host}.+?)\s+\w+="""
    ]
  }
```