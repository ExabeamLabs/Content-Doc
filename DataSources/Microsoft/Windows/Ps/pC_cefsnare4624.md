#### Parser Content
```Java
{
Name = cef-snare-4624
    Vendor = Microsoft
    Product = Windows
    Lms = ArcSight
    DataType = "windows-4624"
    TimeFormat = "epoch"
    Conditions = ["""|Snare|""", """|Microsoft-Windows-Security-Auditing:4624|"""]
    Fields = [
      """({event_name}An account was successfully logged on)""",
      """({event_code}4624)""",
      """\srt=({time}\d{1,100})""",
      """\sdntdom=({domain}[^\s]{1,2000})""",
      """\sduser=({user}.+?)\s{1,100}\w+=""",
      """\sduid=({logon_id}[^\s]{1,2000})""",
      """\scn1=({logon_type}\d{1,100})""",
      """\sdvchost=({host}[^\s]{1,2000})""",
      """\sdproc=(?:-|({process}[\w:\\.\-]{1,2000}))""",
      """Service_,ID=({user_sid}[^\s]{1,2000})\s""",
      """cs5=({auth_package}[^\s]{1,2000}).+?cs5Label=Auth""",
      """\sdeviceProcessName=({auth_process}[^\s]{1,2000})""",
      """ src=(?:-|({src_ip}[\w:.]{1,2000}))\s{1,100}\w+="""
    ]
    DupFields = ["host->dest_host"]
  }
}
```