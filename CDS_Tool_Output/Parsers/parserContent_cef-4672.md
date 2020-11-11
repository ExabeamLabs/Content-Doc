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
            """\srt=({time}\d+)""",
            """\sdeviceSeverity=({outcome}[^\s]+)""",
            """\sdhost=({host}.+?)(\s+\w+=|\s*$)""",
            """\sexternalId=({event_code}\d+)""",
            """\sduser=({user}.+?)(\s+\w+=|\s*$)""",
            """\sdntdom=({domain}.+?)(\s+\w+=|\s*$)""",
            """\sduid=({login_id}[^\s]+)""",
            """\sdpriv=({privileges}.+?)(\s+\w+=|\s*$)"""
        ]
        DupFields = ["host->dest_host"]
}
```