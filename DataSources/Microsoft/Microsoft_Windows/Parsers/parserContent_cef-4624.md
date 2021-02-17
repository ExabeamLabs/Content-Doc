#### Parser Content
```Java
{
Name = cef-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = ArcSight
    DataType = "windows-4624"
    TimeFormat = "epoch"
    Conditions = ["""|Microsoft|Microsoft Windows|""", """|Microsoft-Windows-Security-Auditing:4624"""]
    Fields = [
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """\srt=({time}\d+)""",
      """\sdntdom=({domain}[^\s]+)""",
      """\sduser=({user}.+?)\s+\w+=""",
      """\sduid=({logon_id}[^\s]+)""",
      """\scn1=({logon_type}\d+)""",
      """\sdvchost=({host}[^\s]+)""",
      """\sdproc=(?:-|({process}[\w:\\.\-]+))""",
      """Service_,ID=({user_sid}[^\s]+)\s""",
      """cs5=({auth_package}[^\s]+).+?cs5Label=Auth""",
      """\sdeviceProcessName=({auth_process}[^\s]+)""",
      """ src=(?:-|({src_ip}[\w:.]+))\s+\w+=""",
    ]
    DupFields = ["host->dest_host"]
  }
```