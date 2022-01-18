#### Parser Content
```Java
{
Name = cef-4672
        Vendor = Microsoft
        Product = Microsoft Windows
        Lms = ArcSight
        DataType = "windows-privileged-access"
        TimeFormat = "epoch"
        Conditions = ["CEF:", "|Microsoft|Microsoft Windows|", "externalId=4672"]
        Fields = [
          """({event_name}Special privileges assigned to new logon)""",
            """\srt=({time}\d{1,100})""",
            """\sdeviceSeverity=({outcome}[^\s]{1,2000})""",
            """\sdhost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
            """\sexternalId=({event_code}\d{1,100})""",
            """\sduser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
            """\sdntdom=({domain}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
            """\sduid=({login_id}[^\s]{1,2000})""",
            """\sdpriv=({privileges}.+?)(\s{1,100}\w+=|\s{0,100}$)"""
        ]
        DupFields = ["host->dest_host"]


}
```