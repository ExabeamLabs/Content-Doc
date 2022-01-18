#### Parser Content
```Java
{
Name = cef-4673
        Vendor = Microsoft
        Product = Microsoft Windows
        Lms = ArcSight
        DataType = "windows-privileged-access"
        TimeFormat = "epoch"
        Conditions = ["CEF:", "|Microsoft|Microsoft Windows|", "|A privileged service was called"]
        Fields = [
          """({event_name}A privileged service was called)""",
            """\srt=({time}\d{1,100})""",
            """\sdeviceSeverity=({outcome}[^\s]{1,2000})""",
            """\sdhost=({host}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sexternalId=({event_code}\d{1,100})""",
            """\sduser=({user}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sdntdom=({domain}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sad.Service:Server=({object_server}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sduid=({login_id}[^\s]{1,2000})""",
            """:Privileges=({privileges}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)"""
        ]
        DupFields = ["host->dest_host"]


}
```