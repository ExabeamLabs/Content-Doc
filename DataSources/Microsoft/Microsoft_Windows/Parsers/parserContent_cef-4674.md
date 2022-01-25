#### Parser Content
```Java
{
Name = cef-4674
        Vendor = Microsoft
        Product = Microsoft Windows
        Lms = ArcSight
        DataType = "windows-privileged-access"
        TimeFormat = "epoch"
        Conditions = ["CEF:", "|Microsoft|Microsoft Windows|", "|An operation was attempted on a privileged object"]
        Fields = [
          """({event_name}An operation was attempted on a privileged object)""",
            """\srt=({time}\d{1,100})""",
            """\sdeviceSeverity=({outcome}[^\s]{1,2000})""",
            """\sdhost=({host}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sexternalId=({event_code}\d{1,100})""",
            """\sduser=({user}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sdntdom=({domain}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sdproc=({process}(({directory}.+?)({process_name}[^\\\/]{1,2000}?)))(\s{1,100}\S+=|\s{0,100}$)""",
            """Object_\,Server=({object_server}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
            """\sduid=({login_id}[^\s]{1,2000})""",
            """Desired_\,Access=({accesses}[^\d]{1,2000}?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)"""
            """\sdpriv=({privileges}.+?)(\s{1,100}[^\s]{1,2000}=|\s{0,100}$)""",
        ]
        DupFields = ["host->dest_host","directory->process_directory"]
}
```