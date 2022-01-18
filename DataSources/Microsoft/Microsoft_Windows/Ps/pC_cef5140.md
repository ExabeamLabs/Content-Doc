#### Parser Content
```Java
{
Name = cef-5140
        Vendor = Microsoft
        Product = Microsoft Windows
        Lms = ArcSight
        DataType = "share-access"
        TimeFormat = "epoch"
        Conditions = [ "|Microsoft|Microsoft Windows|", "A network share object was accessed", "Microsoft-Windows-Security-Auditing:5140|"]
        Fields = [
          """({event_name}A network share object was accessed)""",
          """({event_code}5140)""",
          """\Wrt=({time}\d{1,100})""",
          """\Wsrc=({src_ip}[A-Fa-f0-9.:]{1,2000})""",
          """\Wdhost=({dest_host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wdvchost=({host}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wdst=({dest_ip}[A-Fa-f0-9.:]{1,2000})""",
          """\Wdntdom=({domain}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wduser=({user}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\Wduid=({login_id}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\WfilePath=(?:\\+\*\\+)?({share_name}.+?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """({accesses}Read)""",
          """\Wad\.ShareLocalPath=(?:[\\\?]{1,2000})?(?:\s{0,100}|({share_path}({d_parent}.*?)({d_name}[^\\]{1,2000}?))(\\+)?)(\s{1,100}(\w+|\w+\.\w+)=|\s{0,100}$)""",
          """\WfileType=({file_type}\w+)""",
        ]


}
```