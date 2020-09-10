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
            """\srt=({time}\d+)""",
            """\sdeviceSeverity=({outcome}[^\s]+)""",
            """\sdhost=({host}.+?)(\s+[^\s]+=|\s*$)""",
            """\sexternalId=({event_code}\d+)""",
            """\sduser=({user}.+?)(\s+[^\s]+=|\s*$)""",
            """\sdntdom=({domain}.+?)(\s+[^\s]+=|\s*$)""",
            """\sdproc=({process}(({directory}.+?)({process_name}[^\\\/]+?)))(\s+\S+=|\s*$)""",
            """Object_\,Server=({object_server}.+?)(\s+[^\s]+=|\s*$)""",
            """\sduid=({login_id}[^\s]+)""",
            """Desired_\,Access=({accesses}[^\d]+?)(\s+[^\s]+=|\s*$)"""
            """\sdpriv=({privileges}.+?)(\s+[^\s]+=|\s*$)""",
        ]
        DupFields = ["host->dest_host","directory->process_directory"]
}
```