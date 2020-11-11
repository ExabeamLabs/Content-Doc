#### Parser Content
```Java
{
Name = cef-4776
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-4776"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4776"""]
    Fields = [
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """({event_code}4776)""",
      """\srt=({time}\d+)""",
      """\sshost=({dest_host}[^\s]+)""",
      """src=({dest_ip}[a-fA-F:\d.]+)""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """dvchost=(?!(?:[A-Fa-f:\d.]+))[^\s.]+(\.({domain}[^\s.]+)[^\s]*)"""
      """\sduser=({user}.+?)(@({domain}[^\s.]+)[^\s]*)?\s+\w+=""",
      """\scs4=({result_code}\w+)""",
      """dvc=({host}[^\s]+)""",
      """dvchost=({host}[^\s]+)""",
    ]
  }
```